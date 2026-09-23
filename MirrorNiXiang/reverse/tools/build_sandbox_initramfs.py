# -*- coding: utf-8 -*-
# build_sandbox_initramfs.py
# 用途: 从 D:\Project\MirrorNiXiang\image.tar (OCI, 17 层未压缩 tar) 与 Alpine initramfs-virt
#       流式构建自举 initramfs (cpio.gz), 用于在 QEMU 中运行 app/chatgpt-mirror-gateway 沙箱。
#       组成: L1 Debian13 全量根 + L2 ca-certificates/tzdata + L5 libcurl 依赖闭包 + L9/L10 网关
#             + L11 curl-impersonate(仅动态库) + L16/L17 入口脚本与数据目录 + busybox + 内核模块。
#       符号链接/权限在 CPIO 内原样保留, 不落到 Windows 文件系统。
# author: MingTea (reverse tooling)

import gzip
import hashlib
import json
import os
import struct
import sys
import tarfile
import traceback

REVERSE = r'D:\Project\MirrorNiXiang\reverse'
IMAGE = r'D:\Project\MirrorNiXiang\image.tar'
INVIRT = os.path.join(REVERSE, 'tools', 'downloads', 'initramfs-virt')
OUT = os.path.join(REVERSE, 'tools', 'sandbox-initramfs.cpio.gz')
MANIFEST = os.path.join(REVERSE, 'tools', 'sandbox-initramfs.manifest.txt')

LAYERS = {
    1: '411a8667', 2: 'ebad5593', 3: 'f19f6d6c', 5: '2c2d3479', 8: 'ce6817df',
    9: '7a4d7744', 10: 'f58eb8fc', 11: 'b1b92536', 16: '581a524a', 17: 'ba8be979',
}

# L1 提供的基础库, 外部闭包解析时视为已满足
BASE_LIBS = {'libc.so.6', 'libm.so.6', 'libpthread.so.0', 'libdl.so.2', 'librt.so.1',
             'libgcc_s.so.1', 'libstdc++.so.6', 'ld-linux-x86-64.so.2'}

# 解析 .so 依赖用的库目录搜索前缀
LIB_DIRS = ['usr/lib/x86_64-linux-gnu/', 'lib/x86_64-linux-gnu/', 'usr/lib64/',
            'lib64/', 'usr/lib/', 'lib/', 'usr/local/lib/']

INIT_SCRIPT = r'''#!/usr/bin/busybox sh
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
unset LD_PRELOAD CURL_IMPERSONATE
/usr/bin/busybox mount -t proc proc /proc
/usr/bin/busybox mount -t sysfs sysfs /sys
/usr/bin/busybox mount -t devtmpfs devtmpfs /dev
echo '====== SANDBOX BOOT ======'
/usr/bin/busybox uname -a
echo '--- merged-usr / modules check ---'
/usr/bin/busybox ls -ld /lib /lib64 /sbin /usr/lib/modules /usr/lib/modules/6.18.52-0-virt 2>&1
echo '--- loader ---'
/lib64/ld-linux-x86-64.so.2 --version 2>&1 | /usr/bin/busybox head -1
echo '--- curl-impersonate dir ---'
/usr/bin/busybox ls -l /opt/curl-impersonate/ 2>&1 | /usr/bin/busybox head -8
echo '--- network ---'
/usr/bin/busybox ip link set lo up 2>&1
/usr/bin/busybox ifconfig lo 127.0.0.1 netmask 255.0.0.0 up 2>&1
/usr/bin/busybox ifconfig lo 2>&1 | /usr/bin/busybox head -3
/usr/bin/busybox modprobe e1000 2>&1
[ -e /sys/class/net/eth0 ] || { echo 'e1000 modprobe failed -> insmod fallback'; /usr/bin/busybox insmod /usr/lib/modules/6.18.52-0-virt/kernel/drivers/net/ethernet/intel/e1000/e1000.ko 2>&1; }
/usr/bin/busybox ifconfig eth0 10.0.2.15 netmask 255.255.255.0 up 2>&1
/usr/bin/busybox route add default gw 10.0.2.2 2>&1
echo 'nameserver 10.0.2.3' > /etc/resolv.conf
echo '--- gateway deps (glibc ld --list) ---'
LD_PRELOAD=/opt/curl-impersonate/libcurl-impersonate.so /lib64/ld-linux-x86-64.so.2 --list /app/chatgpt-mirror-gateway 2>&1 | /usr/bin/busybox head -25
echo '--- starting gateway ---'
/usr/bin/busybox mkdir -p /app/data /run
export HOST=0.0.0.0 PORT=40002 DATABASE_PATH=/app/data/chatgpt_mirror.db
export GATEWAY_ADMIN_SECRET=sandbox-gateway-secret-0001
export CREDENTIAL_ENCRYPTION_KEY=sandbox-credential-key-00000000000000000000000000
export DJANGO_UPSTREAM=http://10.0.2.2:18080 ADMIN_UPSTREAM=http://10.0.2.2:18080
export CF_BYPASS_URL=http://10.0.2.2:18081 CF_BYPASS_SECRET=sandbox-gateway-secret-0001
export REQUEST_TIMEOUT_SECS=20
cd /app
LD_PRELOAD=/opt/curl-impersonate/libcurl-impersonate.so CURL_IMPERSONATE=chrome146 ./chatgpt-mirror-gateway >/app/gateway.log 2>&1 &
echo "gateway pid $!"
/usr/bin/busybox sleep 3
echo '--- gateway.log ---'
/usr/bin/busybox cat /app/gateway.log 2>/dev/null
/usr/bin/busybox sleep 1
echo '--- listening ports ---'
/usr/bin/busybox netstat -ltn 2>/dev/null || /usr/bin/busybox cat /proc/net/tcp
echo '--- ifconfig eth0 ---'
/usr/bin/busybox ifconfig eth0 2>&1 | /usr/bin/busybox head -6
echo '--- local http probe (127.0.0.1:40002) ---'
/usr/bin/busybox wget -O- -T 3 http://127.0.0.1:40002/ >/tmp/probe.out 2>&1 &
WPID=$!
/usr/bin/busybox sleep 5
/usr/bin/busybox kill -9 $WPID 2>/dev/null
/usr/bin/busybox head -c 300 /tmp/probe.out
echo ''
echo '====== SANDBOX READY (interactive sh) ======'
while :; do
  /usr/bin/busybox sh
  /usr/bin/busybox echo '[shell exited; respawning]'
  /usr/bin/busybox sleep 1
done
'''


class Cpio:
    def __init__(self, path, gz):
        self.path = path
        self.gz = gz
        self.ino = 100
        self.count = 0
        self.emitted = set()

    def _pad(self):
        off = self.gz.tell()
        p = (-off) % 4
        if p:
            self.gz.write(b'\x00' * p)

    def add(self, name, mode, kind='reg', data=None, stream=None, size=None,
            linkname=None, mtime=0, rdev=(0, 0)):
        if name in self.emitted:
            return False
        if kind == 'dir':
            mode_full = 0o040755
            size = 0
        elif kind == 'sym':
            mode_full = 0o120777
            body = linkname.encode('utf-8')
            size = len(body)
            data = body
        elif kind == 'chr':
            mode_full = 0o020000 | (mode & 0o7777)
            size = 0
        elif kind == 'blk':
            mode_full = 0o060000 | (mode & 0o7777)
            size = 0
        else:
            mode_full = 0o100000 | (mode & 0o7777)
        if size is None:
            size = len(data) if isinstance(data, (bytes, bytearray)) else 0
        self.ino += 1
        nb = name.encode('utf-8') + b'\x00'
        fields = (self.ino, mode_full, 0, 0, 1, int(mtime), size,
                  0, 0, rdev[0], rdev[1], len(nb), 0)
        self.gz.write(b'070701' + b''.join(b'%08X' % v for v in fields))
        self.gz.write(nb)
        self._pad()
        if kind == 'sym':
            self.gz.write(data)
        elif stream is not None:
            left = size
            while left > 0:
                chunk = stream.read(min(1 << 20, left))
                if not chunk:
                    raise IOError('short read for %s' % name)
                self.gz.write(chunk)
                left -= len(chunk)
        elif data:
            self.gz.write(data)
        self._pad()
        self.emitted.add(name)
        self.count += 1
        return True


class BlobReader:
    """独立文件句柄 + 边界限制的 OCI blob 读取器, 供每层 tar 单独使用, 避免共享句柄交错。"""

    def __init__(self, path, offset, size):
        self._f = open(path, 'rb')
        self._f.seek(offset)
        self._off = offset
        self._size = size
        self._pos = 0
        self.name = '<blob@%d+%d>' % (offset, size)

    def read(self, n=-1):
        if n is None or n < 0:
            n = self._size - self._pos
        else:
            n = min(n, self._size - self._pos)
        if n <= 0:
            return b''
        b = self._f.read(n)
        self._pos += len(b)
        return b

    def seek(self, pos, whence=0):
        if whence == 0:
            np_ = pos
        elif whence == 1:
            np_ = self._pos + pos
        else:
            np_ = self._size + pos
        np_ = max(0, min(np_, self._size))
        self._f.seek(self._off + np_)
        self._pos = np_
        return self._pos

    def tell(self):
        return self._pos

    def close(self):
        self._f.close()


def norm_name(raw):
    nm = raw
    if nm.startswith('./'):
        nm = nm[2:]
    return nm


def elf_needed(data):
    """返回 ELF64 动态库的 NEEDED 列表; 解析失败返回 []。"""
    try:
        e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
        e_shentsize = struct.unpack_from('<H', data, 0x3A)[0]
        e_shnum = struct.unpack_from('<H', data, 0x3C)[0]
        e_shstrndx = struct.unpack_from('<H', data, 0x3E)[0]
        secs = []
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            nm, typ, fl, ad, of, sz, lk, inf, al, es = struct.unpack_from('<IIQQQQIIQQ', data, off)
            secs.append(dict(n=nm, off=of))
        shstr = secs[e_shstrndx]

        def sn(i):
            e = data.index(b'\x00', shstr['off'] + i)
            return data[shstr['off'] + i:e].decode('utf-8', 'replace')

        byname = {}
        for s in secs:
            s['sn'] = sn(s['n'])
            byname.setdefault(s['sn'], s)
        dyn = byname.get('.dynamic')
        dynstr = byname.get('.dynstr')
        if not dyn or not dynstr:
            return []
        o = dyn['off']
        needed = []
        for _ in range(600):
            tag, val = struct.unpack_from('<qQ', data, o)
            if tag == 0:
                break
            if tag == 1:
                e = data.index(b'\x00', dynstr['off'] + val)
                needed.append(data[dynstr['off'] + val:e].decode('utf-8', 'replace'))
            o += 16
        return needed
    except Exception:
        # 解析失败必须可见, 避免闭包解析静默漏掉依赖
        print('WARN elf_needed parse failed', file=sys.stderr)
        return []


def parse_virt_initrd(path):
    """流式返回 (name, mode, filesize, kind, data) 列表; 交由调用方按需 emit。"""
    entries = []
    with gzip.open(path, 'rb') as f:
        while True:
            hdr = f.read(110)
            if len(hdr) < 110 or hdr[:6] != b'070701':
                break
            fl = [int(hdr[6 + i * 8:14 + i * 8], 16) for i in range(13)]
            ino, mode, uid, gid, nlink, mtime, filesize = fl[0], fl[1], fl[2], fl[3], fl[4], fl[5], fl[6]
            namesize = fl[11]
            name = f.read(namesize - 1).decode('utf-8', 'replace')
            f.read(1)
            pad = (4 - ((110 + namesize) % 4)) % 4
            f.read(pad)
            if name == 'TRAILER!!!':
                break
            ftype = mode & 0o170000
            if ftype == 0o120000:
                data = f.read(filesize)
            elif ftype == 0o100000:
                data = f.read(filesize) if filesize <= (8 << 20) else None
                if data is None:
                    # 大文件不缓冲, 直接跳过数据区与对齐填充
                    print('WARN parse_virt_initrd: skipping large member %s (%d bytes)'
                          % (name, filesize), file=sys.stderr)
                    dpad = (4 - (filesize % 4)) % 4
                    f.seek(filesize + dpad, 1)
                    continue
            else:
                data = b''
            dpad = (4 - (filesize % 4)) % 4
            f.read(dpad)
            if ftype == 0o100000:
                kind = 'reg'
            elif ftype == 0o120000:
                kind = 'sym'
            elif ftype == 0o040000:
                kind = 'dir'
            else:
                kind = 'other'
            entries.append((name, mode, filesize, kind, data, None))
    return entries


def main():
    log = []

    def L(msg):
        print(msg)
        log.append(msg)

    outer = tarfile.open(IMAGE, 'r:')
    outer_map = {m.name: m for m in outer.getmembers()}
    man = json.loads(outer.extractfile(outer_map['manifest.json']).read().decode('utf-8'))[0]
    layer_paths = man['Layers']
    blob_keep = []

    def layer_path(prefix):
        for p in layer_paths:
            if p.split('/')[-1].startswith(prefix):
                return p
        raise KeyError(prefix)

    tfs = {}

    def tfile(idx):
        if idx not in tfs:
            member = outer_map[layer_path(LAYERS[idx])]
            br = BlobReader(IMAGE, member.offset_data, member.size)
            blob_keep.append(br)
            tfs[idx] = tarfile.open(fileobj=br, mode='r:')
        return tfs[idx]

    # ---------- 1) 名称索引 (供闭包解析) ----------
    maps = {}
    for idx in (1, 2, 3, 5, 8):
        m = {}
        for member in tfile(idx):
            nm = norm_name(member.name)
            if not nm or nm == '.':
                continue
            m[nm] = member
        maps[idx] = m
        L('index L%-2d entries=%d' % (idx, len(m)))

    present = set(maps[1]) | set(maps[2])
    present_basenames = set(os.path.basename(p) for p in present if '/' in p) | set(present)

    def find_member(name, order=(5, 3, 8)):
        for idx in order:
            m = maps.get(idx, {})
            for d in LIB_DIRS:
                cand = d + name
                if cand in m and not m[cand].isdir():
                    return idx, cand
            for cand, member in m.items():
                if cand.endswith('/' + name) and not member.isdir():
                    return idx, cand
        return None, None

    def resolve_symlink_chain(idx, path, seen=None):
        """返回该路径需要一并加入的 (idx, path) 列表 (含自身与链接目标文件)。"""
        out = []
        seen = seen or set()
        cur = path
        for _ in range(6):
            if cur in seen:
                break
            seen.add(cur)
            member = maps[idx].get(cur)
            if member is None:
                break
            out.append((idx, cur))
            if member.issym():
                tgt = member.linkname
                if tgt.startswith('/'):
                    nxt = norm_name(tgt.lstrip('/'))
                else:
                    nxt = os.path.normpath(os.path.join(os.path.dirname(cur), tgt)).replace('\\', '/')
                if nxt in maps[idx]:
                    cur = nxt
                    continue
                # 同目录基名兜底
                alt = os.path.dirname(cur) + '/' + os.path.basename(tgt)
                if alt in maps[idx]:
                    cur = alt
                    continue
            break
        return out

    # ---------- 2) L5 libcurl 依赖闭包 ----------
    closure = {}          # (idx,path) -> reason
    unresolved = []
    queue = ['libcurl.so.4']
    seen_names = set(queue)
    while queue:
        want = queue.pop(0)
        if want in BASE_LIBS or want in present_basenames:
            continue
        idx, path = find_member(want)
        if idx is None:
            unresolved.append(want)
            continue
        entries = resolve_symlink_chain(idx, path)
        added = False
        for i2, p2 in entries:
            if (i2, p2) not in closure:
                closure[(i2, p2)] = want
                added = True
        regpath = None
        for i2, p2 in entries:
            if maps[i2][p2].isreg():
                regpath = (i2, p2)
        if regpath:
            i2, p2 = regpath
            data = tfile(i2).extractfile(maps[i2][p2]).read()
            for dep in elf_needed(data):
                if dep not in seen_names and dep not in present_basenames:
                    seen_names.add(dep)
                    queue.append(dep)
        if added:
            L('closure + %-28s <= %s (L%d %s)' % (want, 'L%d' % idx, idx, path))

    closure_bytes = sum(maps[i][p].size for i, p in closure)
    L('closure entries=%d bytes=%d unresolved=%s' % (len(closure), closure_bytes, unresolved or 'none'))

    # ---------- 3) 写 CPIO ----------
    tmp = OUT + '.tmp'
    raw = open(tmp, 'wb')
    gz = gzip.GzipFile(filename='', mode='wb', fileobj=raw, compresslevel=6, mtime=0)
    cp = Cpio(OUT, gz)
    src_stats = []

    def emit_layer(idx, filt, label):
        n = 0
        pending_links = []
        perl_buf = None
        for member in tfile(idx):
            nm = norm_name(member.name)
            if not nm or nm == '.':
                continue
            if not filt(nm, member):
                continue
            if member.isdir():
                if cp.add(nm, member.mode, kind='dir', mtime=member.mtime):
                    n += 1
            elif member.issym():
                if cp.add(nm, 0, kind='sym', linkname=member.linkname, mtime=member.mtime):
                    n += 1
            elif member.islnk():
                pending_links.append((nm, member.linkname, member.mode, member.mtime))
            elif member.isreg():
                st = tfile(idx).extractfile(member)
                if nm == 'usr/bin/perl':
                    perl_buf = st.read()
                    cp.add(nm, member.mode, data=perl_buf, mtime=member.mtime)
                else:
                    cp.add(nm, member.mode, stream=st, size=member.size, mtime=member.mtime)
                n += 1
            elif member.ischr() or member.isblk():
                if cp.add(nm, member.mode, kind='chr' if member.ischr() else 'blk',
                          rdev=(member.devmajor, member.devminor), mtime=member.mtime):
                    n += 1
        for nm, target, mode, mtime in pending_links:
            tgt = 'usr/bin/perl'
            if nm == 'usr/bin/perl5.40.1' and target == 'usr/bin/perl' and perl_buf:
                cp.add(nm, mode, data=perl_buf, mtime=mtime)
            else:
                cp.add(nm, 0, kind='sym', linkname='/' + target, mtime=mtime)
            n += 1
        src_stats.append((label, n))
        L('emit %-32s entries=%d' % (label, n))

    # L1 / L2 全量
    emit_layer(1, lambda nm, m: True, 'L1 debian-rootfs')
    emit_layer(2, lambda nm, m: True, 'L2 ca-certificates')

    # L5 闭包
    n = 0
    for i, p in sorted(closure):
        member = maps[i][p]
        if member.issym():
            cp.add(p, 0, kind='sym', linkname=member.linkname, mtime=member.mtime)
        else:
            st = tfile(i).extractfile(member)
            cp.add(p, member.mode, stream=st, size=member.size, mtime=member.mtime)
        n += 1
    src_stats.append(('L5 libcurl closure', n))
    L('emit %-32s entries=%d' % ('L5 libcurl closure', n))

    # L9/L10/L16/L17
    emit_layer(9, lambda nm, m: True, 'L9 app dir')
    emit_layer(10, lambda nm, m: nm.endswith('chatgpt-mirror-gateway'), 'L10 gateway')
    emit_layer(16, lambda nm, m: True, 'L16 entry script')
    emit_layer(17, lambda nm, m: True, 'L17 data dirs/symlinks')

    # L11 curl-impersonate (排除 .a 与头文件)
    emit_layer(11, lambda nm, m: ('.a' not in nm) and ('/include/' not in nm), 'L11 curl-impersonate(so)')

    # initramfs-virt: busybox(动态 musl, 需 ld-musl 加载器) + 内核模块
    virt = parse_virt_initrd(INVIRT)
    n = 0
    kernel_rel = None
    VIRT_KEEP = {'usr/bin/busybox', 'usr/lib/ld-musl-x86_64.so.1', 'usr/lib/libc.musl-x86_64.so.1'}
    for name, mode, filesize, kind, data, fh in virt:
        keep = name in VIRT_KEEP or name.startswith('usr/lib/modules')
        if keep and kernel_rel is None and name.startswith('usr/lib/modules/'):
            parts = name.split('/')
            if len(parts) > 3:
                kernel_rel = parts[3]
        if not keep:
            continue
        # 内核 initramfs 解包器不会自动建中间目录, 必须补齐每一级父目录
        parts = name.split('/')
        for i in range(1, len(parts)):
            anc = '/'.join(parts[:i])
            if anc not in cp.emitted:
                cp.add(anc, 0o755, kind='dir')
        if kind == 'sym':
            cp.add(name, mode, kind='sym', linkname=data.decode('utf-8', 'replace'), mtime=0)
        elif kind == 'reg' and data is not None:
            cp.add(name, mode, data=data, mtime=0)
        elif kind == 'dir':
            cp.add(name, mode & 0o7777, kind='dir', mtime=0)
        n += 1
    src_stats.append(('initramfs-virt modules+busybox', n))
    L('emit %-32s entries=%d kernel=%s' % ('initramfs-virt', n, kernel_rel))

    # 目录兜底与自定义文件
    for d in ('opt', 'opt/curl-impersonate', 'app', 'app/data', 'run', 'dev', 'proc', 'sys', 'tmp', 'etc'):
        cp.add(d, 0o755, kind='dir')
    cp.add('init', 0o755, data=INIT_SCRIPT.encode('utf-8'))
    cp.add('etc/hostname', 0o644, data=b'sandbox\n')
    cp.add('etc/resolv.conf', 0o644, data=b'nameserver 10.0.2.3\n')
    cp.add('TRAILER!!!', 0, data=b'')
    gz.close()
    raw.close()
    os.replace(tmp, OUT)

    h = hashlib.sha256()
    with open(OUT, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    L('OUT %s bytes=%d sha256=%s' % (OUT, os.path.getsize(OUT), h.hexdigest()))

    with open(MANIFEST, 'w', encoding='utf-8') as f:
        f.write('sandbox-initramfs manifest\n')
        f.write('source image: %s\n' % IMAGE)
        f.write('output: %s (%d bytes)\n' % (OUT, os.path.getsize(OUT)))
        f.write('sha256: %s\n' % h.hexdigest())
        f.write('cpio entries: %d\n' % cp.count)
        f.write('kernel release (modules): %s\n' % kernel_rel)
        f.write('\n-- sources --\n')
        for label, cnt in src_stats:
            f.write('%-34s %d\n' % (label, cnt))
        f.write('\n-- L5 closure (%d entries, %d bytes) --\n' % (len(closure), closure_bytes))
        for (i, p) in sorted(closure):
            f.write('L%d %-60s %10d  <= %s\n' % (i, p, maps[i][p].size, closure[(i, p)]))
        f.write('\n-- unresolved --\n')
        for u in unresolved:
            f.write('%s\n' % u)
    L('manifest: %s' % MANIFEST)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        traceback.print_exc()
        sys.exit(1)

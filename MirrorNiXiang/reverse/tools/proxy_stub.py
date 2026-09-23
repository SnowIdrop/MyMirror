# -*- coding: utf-8 -*-
# proxy_stub.py — 最小 HTTP 代理桩 (CONNECT 隧道 + absolute-form GET), 用于镜像代理链路验证。
#   python proxy_stub.py <port>
#   每个连接写一行到 logs\proxystub-<port>.log (方法/目标), 便于确认流量是否经过代理。
# author: MingTea (reverse tooling)

import os
import socket
import sys
import threading
import time

LOG_DIR = r'D:\Project\MirrorNiXiang\reverse\logs'


def log(port, line):
    with open(os.path.join(LOG_DIR, 'proxystub-%d.log' % port), 'a', encoding='utf-8') as f:
        f.write('%s %s\n' % (time.strftime('%H:%M:%S'), line))


def relay(a, b):
    try:
        while True:
            data = a.recv(65536)
            if not data:
                break
            b.sendall(data)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass


def handle(conn, port):
    try:
        conn.settimeout(30)
        buf = b''
        while b'\r\n\r\n' not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                return
            buf += chunk
        head = buf.split(b'\r\n\r\n', 1)[0].decode('latin-1')
        first = head.splitlines()[0]
        parts = first.split()
        if len(parts) < 2:
            return
        method, target = parts[0], parts[1]
        if method.upper() == 'CONNECT':
            host, _, p = target.partition(':')
            up = socket.create_connection((host, int(p or '443')), timeout=15)
            conn.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            log(port, 'CONNECT %s' % target)
            t = threading.Thread(target=relay, args=(conn, up), daemon=True)
            t.start()
            relay(up, conn)
            return
        # absolute-form GET/POST
        from urllib.parse import urlsplit
        u = urlsplit(target)
        host = u.hostname
        # 沙箱场景: guest 视角的 10.0.2.2 即宿主回环, 在宿主侧映射回 127.0.0.1
        if host == '10.0.2.2':
            host = '127.0.0.1'
        p = u.port or 80
        path = u.path + (('?' + u.query) if u.query else '')
        up = socket.create_connection((host, p), timeout=15)
        rest = buf[len(buf.split(b'\r\n\r\n', 1)[0]) + 4:]
        newhead = head.replace(target, path, 1).encode('latin-1') + b'\r\n\r\n'
        up.sendall(newhead + rest)
        log(port, '%s %s' % (method, target))
        t = threading.Thread(target=relay, args=(conn, up), daemon=True)
        t.start()
        relay(up, conn)
    except OSError as e:
        log(port, 'ERR %s %r' % (first if 'first' in dir() else '?', e))
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18084
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', port))
    srv.listen(64)
    print('proxy_stub listening %d' % port, flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn, port), daemon=True).start()


if __name__ == '__main__':
    main()

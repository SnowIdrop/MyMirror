# -*- coding: utf-8 -*-
# run_cf_mode_test.py — 切换 cf_fail_stub 模式并重启沙箱网关, 采集该模式下的启动/预热行为。
# 用法: python run_cf_mode_test.py <mode> [wait_seconds]
# author: MingTea (reverse tooling)

import socket
import sys
import time

MODE_FILE = r'D:\Project\MirrorNiXiang\reverse\logs\cfstub-mode.txt'


def drive(cmds, wait_total, chunk=1.0):
    s = socket.create_connection(('127.0.0.1', 45401), timeout=4)
    s.settimeout(1.0)

    def drain(dur):
        end = time.time() + dur
        out = b''
        while time.time() < end:
            try:
                d = s.recv(8192)
                if not d:
                    break
                out += d
            except socket.timeout:
                pass
        return out

    drain(0.3)
    s.sendall(cmds.encode())
    time.sleep(0.4)
    return drain(wait_total)


def main():
    mode = sys.argv[1]
    wait = float(sys.argv[2]) if len(sys.argv) > 2 else 8.0
    with open(MODE_FILE, 'w', encoding='ascii') as f:
        f.write(mode + '\n')
    cmds = (
        "echo ===MODE:%s===\n"
        "GWP=$(for p in /proc/[0-9]*; do /usr/bin/busybox cat $p/cmdline 2>/dev/null | "
        "/usr/bin/busybox grep -q chatgpt-mirror-gateway && echo ${p#/proc/}; done | /usr/bin/busybox head -1)\n"
        "echo old_gw=$GWP; /usr/bin/busybox kill -9 $GWP 2>/dev/null; /usr/bin/busybox sleep 0.5\n"
        "L=$(/usr/bin/busybox wc -l < /app/gateway.log)\n"
        "/usr/bin/busybox sh /app/run-gw5.sh\n"
        "/usr/bin/busybox sleep %d\n"
        "/usr/bin/busybox tail -n +$((L+1)) /app/gateway.log\n"
        "echo ===MODE-END===\n"
    ) % (mode, int(wait))
    out = drive(cmds, wait + 8.0)
    sys.stdout.buffer.write(out[-8000:])


if __name__ == '__main__':
    main()

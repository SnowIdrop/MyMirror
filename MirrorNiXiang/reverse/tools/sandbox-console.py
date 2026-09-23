# -*- coding: utf-8 -*-
# sandbox-console.py — 连接 QEMU 沙箱串口 TCP 控制台 (tcp:127.0.0.1:45401) 的双向桥。
# 用法: python sandbox-console.py  (直接键入命令, Ctrl+C 退出)
import socket
import sys
import threading
import time


def main():
    s = None
    for _ in range(80):
        try:
            s = socket.create_connection(('127.0.0.1', 45401), timeout=2)
            s.settimeout(None)
            break
        except OSError:
            time.sleep(0.25)
    if s is None:
        print('无法连接 127.0.0.1:45401 (沙箱未运行?)')
        return 1
    print('[已连接沙箱串口 45401；直接输入命令，Ctrl+C 退出]', flush=True)

    def pump_in():
        while True:
            b = sys.stdin.buffer.read(1)
            if not b:
                break
            try:
                s.sendall(b)
            except OSError:
                break

    threading.Thread(target=pump_in, daemon=True).start()
    try:
        while True:
            d = s.recv(4096)
            if not d:
                print('[连接已关闭]')
                break
            sys.stdout.buffer.write(d)
            sys.stdout.buffer.flush()
    except KeyboardInterrupt:
        pass
    s.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

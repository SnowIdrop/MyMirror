# -*- coding: utf-8 -*-
# cf_fail_stub.py — cfbypass 故障模式桩:
#   python cf_fail_stub.py <port> [default_mode]
#   模式从 logs\cfstub-mode.txt 逐请求读取(不存在则用 default_mode/ok), 取值:
#     ok | empty | partial | 401 | 502 | hang
#   仅实现 POST /cloudflare5s/bypass-v1|v2 与 GET /healthz, 请求追加 logs\cfstub-<port>.log
# author: MingTea (reverse tooling)

import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG_DIR = r'D:\Project\MirrorNiXiang\reverse\logs'
MODE_FILE = os.path.join(LOG_DIR, 'cfstub-mode.txt')

UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
      '(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36')
FULL = {'user_agent': UA, 'cookies': [
    {'name': 'cf_clearance', 'value': 'STUB_CF_CLEARANCE_0001', 'domain': '.chatgpt.com'},
    {'name': '__cf_bm', 'value': 'STUB_CF_BM_0001', 'domain': '.chatgpt.com'}]}
PARTIAL = {'user_agent': UA, 'cookies': [
    {'name': '__cf_bm', 'value': 'STUB_CF_BM_ONLY', 'domain': '.chatgpt.com'}]}
EMPTY = {'user_agent': UA, 'cookies': []}


def current_mode(default_mode):
    try:
        with open(MODE_FILE, encoding='utf-8') as f:
            m = f.read().strip()
            if m:
                return m
    except OSError:
        pass
    return default_mode


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    default_mode = 'ok'

    def _send(self, status, obj):
        body = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0) or 0)
        body = self.rfile.read(length) if length else b''
        mode = current_mode(self.default_mode)
        with open(os.path.join(LOG_DIR, 'cfstub-%d.log' % self.server.server_address[1]),
                  'a', encoding='utf-8') as f:
            f.write(json.dumps({'ts': time.strftime('%H:%M:%S'), 'mode': mode,
                                'path': self.path,
                                'auth': self.headers.get('Authorization', ''),
                                'body': body[:500].decode('utf-8', 'replace')},
                               ensure_ascii=False) + '\n')
        if self.path.startswith('/cloudflare5s/bypass'):
            if mode == '401':
                self._send(401, {'detail': 'invalid cf bypass secret'})
            elif mode == '502':
                self._send(502, {'detail': 'upstream chromium crashed'})
            elif mode == 'hang':
                time.sleep(60)
                self._send(200, FULL)
            elif mode == 'empty':
                self._send(200, EMPTY)
            elif mode == 'partial':
                self._send(200, PARTIAL)
            else:
                self._send(200, FULL)
        else:
            self._send(404, {'detail': 'not found'})

    def do_GET(self):
        if self.path == '/healthz':
            self._send(200, {'status': 'ok', 'headless': False})
        else:
            self._send(404, {'detail': 'not found'})

    def log_message(self, fmt, *args):
        pass


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18083
    default = sys.argv[2] if len(sys.argv) > 2 else 'ok'
    Handler.default_mode = default
    srv = ThreadingHTTPServer(('127.0.0.1', port), Handler)
    srv.daemon_threads = True
    print('cf_fail_stub listening %d default=%s' % (port, default), flush=True)
    srv.serve_forever()


if __name__ == '__main__':
    main()

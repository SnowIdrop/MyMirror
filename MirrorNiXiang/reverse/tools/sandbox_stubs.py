# -*- coding: utf-8 -*-
# sandbox_stubs.py — QEMU 沙箱配套宿主桩服务:
#   127.0.0.1:18080 Django(DJANGO_UPSTREAM/ADMIN_UPSTREAM) 桩
#   127.0.0.1:18081 cfbypass 桩 (POST /cloudflare5s/bypass-v1|v2 -> {user_agent, cookies[]})
#   127.0.0.1:18082 ChatGPT 上游桩 (记录网关出站请求并回固定响应)
# 所有请求以 JSON Lines 追加到 reverse\logs\stub-<port>.log
# author: MingTea (reverse tooling)

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG_DIR = r'D:\Project\MirrorNiXiang\reverse\logs'


def log(port, entry):
    path = os.path.join(LOG_DIR, 'stub-%d.log' % port)
    with open(path, 'a', encoding='utf-8') as f:
        f.write(json.dumps(entry, ensure_ascii=False) + '\n')
    print('[stub %d] %s %s' % (port, entry.get('method'), entry.get('path')), flush=True)


class StubHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def _handle(self):
        length = 0
        try:
            length = int(self.headers.get('Content-Length', 0) or 0)
        except ValueError:
            length = 0
        body = self.rfile.read(length) if length else b''
        port = self.server.server_address[1]
        entry = {
            'ts': time.strftime('%Y-%m-%d %H:%M:%S'),
            'port': port,
            'method': self.command,
            'path': self.path,
            'headers': {k: v for k, v in self.headers.items()},
            'body': body[:4096].decode('utf-8', 'replace'),
        }
        log(port, entry)
        self.responder(self, entry)

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def do_PUT(self):
        self._handle()

    def do_DELETE(self):
        self._handle()

    def do_PATCH(self):
        self._handle()

    def do_HEAD(self):
        self._handle()

    def log_message(self, fmt, *args):
        pass


def send_json(h, obj, status=200):
    payload = json.dumps(obj, ensure_ascii=False).encode('utf-8')
    h.send_response(status)
    h.send_header('Content-Type', 'application/json')
    h.send_header('Content-Length', str(len(payload)))
    h.end_headers()
    h.wfile.write(payload)


def send_text(h, text, status=200, ctype='text/html; charset=utf-8'):
    payload = text.encode('utf-8')
    h.send_response(status)
    h.send_header('Content-Type', ctype)
    h.send_header('Content-Length', str(len(payload)))
    h.end_headers()
    h.wfile.write(payload)


def django_responder(h, entry):
    send_json(h, {'stub': 'django', 'path': entry['path'], 'method': entry['method']})


def cf_responder(h, entry):
    if entry['path'].startswith('/cloudflare5s/bypass'):
        send_json(h, {
            'user_agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                           '(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36'),
            'cookies': [
                {'name': 'cf_clearance', 'value': 'STUB_CF_CLEARANCE_0001', 'domain': '.chatgpt.com'},
                {'name': '__cf_bm', 'value': 'STUB_CF_BM_0001', 'domain': '.chatgpt.com'},
            ],
        })
    elif entry['path'] == '/healthz':
        send_json(h, {'status': 'ok', 'headless': False})
    else:
        send_json(h, {'message': 'ok'})


def upstream_responder(h, entry):
    # 路径含 hang 时故意挂起, 用于验证网关的请求超时行为
    if 'hang' in entry['path']:
        time.sleep(65)
    send_text(h, 'UPSTREAM_STUB_OK path=%s method=%s' % (entry['path'], entry['method']))


def make_handler(responder):
    class H(StubHandler):
        pass
    # 以 staticmethod 绑定, 避免实例化后自动附加 self 导致参数错位
    H.responder = staticmethod(responder)
    return H


def main():
    specs = [
        (18080, django_responder),
        (18081, cf_responder),
        (18082, upstream_responder),
    ]
    for port, responder in specs:
        srv = ThreadingHTTPServer(('127.0.0.1', port), make_handler(responder))
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        print('listening %d' % port, flush=True)
    print('STUBS READY on 18080/18081/18082', flush=True)
    while True:
        time.sleep(3600)


if __name__ == '__main__':
    main()

"""Synthetic TLS provider oracle. Requires CERT_PEM/KEY_PEM prepended by the host.
Author: MingTea. No network adapter: the logical public address is bound to guest lo.
"""
import http.client, http.server, json, os, ssl, subprocess, threading, time

assert os.environ.get('GATEWAY_TEST_SUBJECT') in ('original', 'candidate', 'rollback')
assert set(os.listdir('/sys/class/net')) == {'lo'}, 'Refusing a guest with a network adapter'
def emit(value):
    print('RESULT:' + json.dumps(value, ensure_ascii=False), flush=True)

logical = '93.184.216.34'
subprocess.run(['/usr/bin/busybox', 'ip', 'addr', 'add', logical + '/32', 'dev', 'lo'], check=True)
for path, content in [('/tmp/provider-cert.pem', CERT_PEM), ('/tmp/provider-key.pem', KEY_PEM), ('/tmp/provider-ca.pem', ROOT_PEM)]:
    with open(path, 'w') as file:
        file.write(content)
os.makedirs('/etc/ssl/certs', exist_ok=True)
with open('/etc/ssl/certs/ca-certificates.crt', 'a') as file:
    file.write('\n' + ROOT_PEM)
for path in ['/etc/ssl/cert.pem', '/etc/pki/tls/cert.pem', '/usr/local/share/certs/ca-root-nss.crt']:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'a') as file:
        file.write('\n' + ROOT_PEM)

response_text = 'ALLOW'
class Provider(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        emit({'kind':'upstream', 'path':self.path, 'headers':list(self.headers.items()), 'body':raw.decode()})
        data = json.dumps({'choices':[{'message':{'content':response_text}}], 'output_text':response_text,
                           'content':[{'type':'text','text':response_text}],
                           'candidates':[{'content':{'parts':[{'text':response_text}]}}]}).encode()
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(data)))
        self.end_headers()
        self.wfile.write(data)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('/tmp/provider-cert.pem', '/tmp/provider-key.pem')
class TLSServer(http.server.ThreadingHTTPServer):
    def get_request(self):
        socket, peer = super().get_request()
        try:
            wrapped = context.wrap_socket(socket, server_side=True)
            emit({'kind':'tls','peer':peer[0],'version':wrapped.version()})
            return wrapped, peer
        except ssl.SSLError as failure:
            emit({'kind':'tls_error','peer':peer[0],'error':str(failure)})
            socket.close()
            raise
provider = TLSServer(('0.0.0.0', 18443), Provider)
threading.Thread(target=provider.serve_forever, daemon=True).start()
env = dict(PATH=os.environ['PATH'], HOST='127.0.0.1', PORT='40110', DATABASE_PATH='/tmp/provider.db',
           GATEWAY_ADMIN_SECRET='contract-admin-secret-0001', CREDENTIAL_ENCRYPTION_KEY='contract-encryption-key-000000000000001',
           DJANGO_UPSTREAM='http://127.0.0.1:18090', CHATGPT_BASE_URL='http://127.0.0.1:18090',
           REQUEST_TIMEOUT_SECS='2', GATEWAY_COMPAT_PROFILE='original', SSL_CERT_FILE='/tmp/provider-ca.pem',
           SSL_CERT_DIR='/etc/ssl/certs')
binary = os.environ['GATEWAY_TEST_BINARY']
stdout = open('/tmp/provider-gateway.out','w+')
stderr = open('/tmp/provider-gateway.err','w+')
process = subprocess.Popen([binary],env=env,stdout=stdout,stderr=stderr)
try:
    for _ in range(100):
        try:
            connection=http.client.HTTPConnection('127.0.0.1',40110,timeout=.2)
            connection.connect(); connection.close(); break
        except OSError:
            if process.poll() is not None: raise RuntimeError('Gateway exited')
            time.sleep(.1)
    for protocol in ['openai_chat','openai_responses','anthropic_messages','gemini_generate_content']:
        payload={'enabled':False,'protocol':protocol,'model':'synthetic-model','api_key':'synthetic-provider-key',
                 'base_url':'https://'+logical+':18443/v1','mode':'relaxed','custom_terms':[]}
        connection=http.client.HTTPConnection('127.0.0.1',40110,timeout=30)
        connection.request('POST','/api/political-moderation-config/test',json.dumps(payload),
                           {'Content-Type':'application/json','Authorization':'Bearer '+env['GATEWAY_ADMIN_SECRET']})
        response=connection.getresponse()
        emit({'kind':'scenario','id':protocol,'input':payload,'status':response.status,'headers':response.getheaders(),
              'body':response.read().decode()})
        connection.close()
finally:
    process.terminate(); process.wait(timeout=10)
    stdout.seek(0); stderr.seek(0)
    emit({'kind':'process','exit':process.returncode,'stdout':stdout.read(),'stderr':stderr.read()})
    provider.shutdown(); provider.server_close()

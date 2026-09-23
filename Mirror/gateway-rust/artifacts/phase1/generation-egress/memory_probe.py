"""Synthetic native-process in-memory diagnosis only. Never reads a token file."""
from pathlib import Path
import hashlib, http.client, http.server, json, os, socket, subprocess, tempfile, threading, time

here=Path(__file__).resolve().parent
root=here.parents[2]
binary=root/'.build/phase1-candidate-tests/debug/mirror-gateway.exe'
calls=[]
class Stub(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_GET(self):
        assert self.path=='/backend-api/me'
        assert self.headers['Authorization']=='Bearer SYNTHETIC_NOT_A_REAL_TOKEN'
        calls.append({'method':'GET','path':self.path})
        raw=json.dumps({'email':'synthetic@example.invalid','id':'synthetic','name':'Synthetic'}).encode()
        self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
stub=http.server.ThreadingHTTPServer(('127.0.0.1',0),Stub)
threading.Thread(target=stub.serve_forever,daemon=True).start()
with socket.socket() as reserved:
    reserved.bind(('127.0.0.1',0));port=reserved.getsockname()[1]
env=os.environ.copy();origin=f'http://127.0.0.1:{stub.server_port}'
env.update({'HOST':'127.0.0.1','PORT':str(port),'DATABASE_PATH':':memory:',
    'GATEWAY_ADMIN_SECRET':'memory-fixture-admin-secret','CREDENTIAL_ENCRYPTION_KEY':'memory-fixture-encryption-key-00001',
    'GATEWAY_COMPAT_PROFILE':'mirror','GATEWAY_UPSTREAM_MODE':'offline','DJANGO_UPSTREAM':origin,'CHATGPT_BASE_URL':origin,'CHATGPT_CDN_BASE_URL':origin,'COOKIE_SECURE':'false','RUST_LOG':'off'})
env.pop('CF_BYPASS_URL',None)
with tempfile.TemporaryDirectory(prefix='mirror-memory-synthetic-') as cwd:
    process=subprocess.Popen([str(binary)],cwd=cwd,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        for _ in range(100):
            try:
                with socket.create_connection(('127.0.0.1',port),.1): break
            except OSError:
                if process.poll() is not None: raise RuntimeError('fixture process exited')
                time.sleep(.05)
        client=http.client.HTTPConnection('127.0.0.1',port,timeout=5)
        headers={'Authorization':'Bearer memory-fixture-admin-secret','Content-Type':'application/json'}
        client.request('POST','/api/diagnose-chatgpt-auth',json.dumps({'access_token':'SYNTHETIC_NOT_A_REAL_TOKEN'}),headers)
        response=client.getresponse(); value=json.loads(response.read()); assert response.status==200 and value['access_token_valid'] is True
        assert not response.getheader('Set-Cookie')
        client.request('GET','/api/backup/export',headers=headers); response=client.getresponse(); backup=json.loads(response.read())
        assert response.status==200 and backup['gateway_sessions']==[] and backup['chatgpt_accounts']==[]
        client.close(); assert len(calls)==1; assert list(Path(cwd).iterdir())==[]
    finally:
        process.terminate();out,err=process.communicate(timeout=10);stub.shutdown();stub.server_close()
record={'scope':'synthetic native process, not live token validation','binary':str(binary),'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'database':':memory:','access_diagnosis':True,'session_and_account_rows':0,'files_created_in_cwd':0,'upstream_calls':calls,'token_file_read':False,'process_exit':process.returncode,'termination':'owned fixture teardown','stdout':out.decode(),'stderr':err.decode()}
(here/'memory-probe.json').write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8')
print(json.dumps(record))

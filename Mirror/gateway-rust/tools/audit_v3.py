"""Supplemental database and upstream audit; does not discard unexplained differences.
Author: MingTea. Authenticated ciphertext and issued-token/DB relationships are checked.
Proxy DB snapshots are compared literally. Management timestamp columns are explicitly scoped.
"""
import argparse,base64,hashlib,json,re,sys
from pathlib import Path
from email.utils import parsedate_to_datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY=hashlib.sha256(b'contract-encryption-key-000000000000001').digest()

def normalize_records(rows,mode):
    tokens={};dates=[]
    def bind(value,identity):
        if isinstance(value,dict):
            for key,child in value.items():bind(child,identity+'/'+key)
        elif isinstance(value,list):
            for index,child in enumerate(value):bind(child,identity+'/'+str(index))
        elif isinstance(value,str) and value.startswith('/api/not-login?user_gateway_token='):
            token=value.split('=',1)[1]
            assert re.fullmatch('[0-9a-f]{32,64}',token)
            tokens['sha256:'+hashlib.sha256(token.encode()).hexdigest()]=identity
    for record in rows:
        if record.get('kind') not in ('scenario','http'):continue
        # 观测脚本对 http 记录写显式 null id；按 id→path→'http' 回退，避免身份标签拼接崩溃
        identity=record.get('id') or record.get('path') or 'http'
        try:bind(json.loads(record['body']),identity)
        except json.JSONDecodeError:pass
        for name,value in record.get('headers',[]):
            if name.lower()=='date':dates.append(parsedate_to_datetime(value).timestamp())
            if name.lower()=='set-cookie' and value.startswith('mirror_token='):
                token=value.split(';',1)[0].split('=',1)[1]
                if token:
                    assert re.fullmatch('[0-9a-f]{32,64}',token)
                    tokens['sha256:'+hashlib.sha256(token.encode()).hexdigest()]=identity+'/cookie'
    seeds=[r for r in rows if r.get('kind')=='seed' and r.get('case','').startswith('visit-log-')]
    scalar_times=[r['input']['created_at'] for r in seeds if isinstance(r['input']['created_at'],int)]
    anchor=scalar_times[0] if scalar_times else None
    def seed_time(value):
        if isinstance(value,list):return [seed_time(x) for x in value]
        assert isinstance(value,int)
        return {'relative_to_first_seed':value-anchor} if anchor is not None and abs(value-anchor)<86400 else value
    seed_times={}
    for seed in seeds:
        values=seed['input']['created_at'];values=values if isinstance(values,list) else [values]
        for value in values:seed_times[value]=seed_time(value)
    def atom(value):
        if isinstance(value,str) and value in tokens:return {'verified_issued_token':tokens[value]}
        if isinstance(value,str) and value.startswith('enc:v1:'):
            raw=base64.urlsafe_b64decode(value[7:]+'='*(-len(value[7:])%4))
            text=AESGCM(KEY).decrypt(raw[:12],raw[12:],None).decode()
            try:text=json.loads(text)
            except json.JSONDecodeError:pass
            return {'format':'enc:v1:','authenticated_plaintext':text}
        return value
    def runtime_time(value):
        if value is None:return None
        assert isinstance(value,int) and value>=0
        if dates and min(dates)-60<=value<=max(dates)+60:return '<validated-runtime-time>'
        return value
    result={}
    for record in rows:
        if record.get('kind')=='db':
            values=[]
            for raw in record['rows']:
                row=[atom(v) for v in raw]
                if mode=='management':
                    if record['table']=='gateway_sessions':
                        assert raw[5] is None or raw[6] is None or raw[5]<=raw[6]
                        row[5]=runtime_time(raw[5]);row[6]=runtime_time(raw[6])
                    elif record['table']=='gateway_settings':row[2]=runtime_time(raw[2])
                    elif record['table']=='visit_logs':row[4]=seed_times.get(raw[4],raw[4])
                values.append(row)
            key='db:'+record['case']+':'+record['table']
            assert key not in result
            result[key]=values
        elif record.get('kind')=='upstream' and (mode=='management' or record.get('case') is not None):
            headers={}
            for name,value in record.get('headers',[]):headers.setdefault(name.lower(),[]).append(value)
            event={'method':record.get('method'),'path':record['path'],'headers':headers,'body':record.get('body','')}
            result.setdefault('upstream:'+str(record.get('case','whole-run')),[]).append(event)
    for seed in seeds:
        value=dict(seed['input']);value['created_at']=seed_time(value['created_at'])
        result['seed:'+seed['case']]=value
    return result

def audit_wire(rows):
    checked=0
    for record in rows:
        if 'body_raw_b64' not in record:continue
        raw=base64.b64decode(record['body_raw_b64'],validate=True)
        assert len(raw)==record['body_raw_length']
        assert hashlib.sha256(raw).hexdigest()==record['body_raw_sha256']
        length=record.get('observed_content_length')
        if length is not None:assert int(length)==len(raw)
        encoding=record.get('content_encoding')
        if encoding=='gzip':
            import gzip
            assert gzip.decompress(raw).decode('utf-8')==record['body']
        elif encoding is None:
            assert raw.decode('utf-8')==record['body']
        checked+=1
    return checked

def main():
    p=argparse.ArgumentParser();p.add_argument('--mode',choices=['proxy','management','headers'],required=True);p.add_argument('baseline');p.add_argument('candidate');p.add_argument('output');a=p.parse_args()
    left=json.loads(Path(a.baseline).read_text(encoding='utf-8'));right=json.loads(Path(a.candidate).read_text(encoding='utf-8'))
    if a.mode=='headers':
        result={'scope':'raw wire length, digest, gzip integrity and decoded-body binding','baseline_checked':audit_wire(left),'candidate_checked':audit_wire(right),'different':0}
    else:
        b=normalize_records(left,a.mode);c=normalize_records(right,a.mode)
        differences=[{'case':key,'baseline':b.get(key),'candidate':c.get(key)} for key in sorted(b.keys()|c.keys()) if b.get(key)!=c.get(key)]
        result={'scope':a.mode+' recorded DB projections, seed time offsets, and upstream request sequences/headers/bodies','cases':len(b.keys()|c.keys()),'matched':len(b.keys()|c.keys())-len(differences),'different':len(differences),'differences':differences}
    Path(a.output).write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k!='differences'}))
    return bool(result['different'])
if __name__=='__main__':sys.exit(main())

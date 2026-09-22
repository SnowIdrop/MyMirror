"""Compare HTTP restore responses and the original eight database relations.
Author: MingTea. Ciphertexts are authenticated; explicit fixture times stay exact.
Only generated timestamps within 120s of the recorded response Date are normalized.
Malformed ciphertext is tied to its exact submitted field, never globally ignored.
"""
import argparse, base64, binascii, hashlib, json, sys
from email.utils import parsedate_to_datetime
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

KEY=hashlib.sha256(b'backup-v3-fixture-key-a-0000000001').digest()
TIMES={'created_at','updated_at','created_time','updated_time'}
TABLES={'chatgpt_accounts','gateway_sessions','gateway_settings','conversation_owners','project_owners',
        'conversation_statistics','conversation_model_statistics','visit_logs'}

def load(path):
    rows=json.loads(Path(path).read_text(encoding='utf-8'))
    result={row['id']:row for row in rows if row['kind']=='case'}
    assert len(result)==sum(row['kind']=='case' for row in rows)
    return result

def canonical(case):
    if not case['startup_ready']:
        return {'startup_ready':False, 'observation_failure':'Gateway did not start; before/after snapshots unavailable'}
    responses=case.get('responses',[])
    dates=[parsedate_to_datetime(value).timestamp() for response in responses for name,value in response['headers'] if name.lower()=='date']
    opaque={}
    def bind(value,path='payload'):
        if isinstance(value,dict):
            for name,item in value.items(): bind(item,path+'/'+name)
        elif isinstance(value,list):
            for index,item in enumerate(value):bind(item,path+'/'+str(index))
        elif isinstance(value,str) and value.startswith('enc:v1:'):
            try:decrypt(value)
            except (InvalidTag,ValueError,binascii.Error):opaque[value]={'submitted_opaque_cipher':path}
    def decrypt(value):
        raw=base64.urlsafe_b64decode(value[7:]+'='*(-len(value[7:])%4))
        return AESGCM(KEY).decrypt(raw[:12],raw[12:],None).decode('utf-8')
    bind(case.get('payload'))
    def norm(value,field=''):
        if isinstance(value,dict):return {k:norm(v,k) for k,v in value.items()}
        if isinstance(value,list):return [norm(item,field) for item in value]
        if isinstance(value,str) and value.startswith('enc:v1:'):
            if value in opaque:return opaque[value]
            return {'format':'enc:v1:','authenticated_plaintext':decrypt(value)}
        if field in TIMES and isinstance(value,int) and dates and min(dates)-120<=value<=max(dates)+120:
            return '<validated-generated-time>'
        return value
    def snapshot(value):
        assert TABLES<=value.keys(), 'Missing original database relation'
        extra=set(value)-TABLES
        assert extra <= {'rust_authorizations'}, 'Unregistered extra relation'
        if 'rust_authorizations' in value:
            assert value['rust_authorizations']['rows']==[], 'Restore fixture acquired an authorization'
        result={}
        for table in sorted(TABLES):
            columns=value[table]['columns']
            rows=[{name:norm(cell,name) for name,cell in zip(columns,row,strict=True)} for row in value[table]['rows']]
            result[table]={'columns':columns,'rows':sorted(rows,key=lambda row:json.dumps(row,sort_keys=True))}
        return result
    wire=[]
    for response in responses:
        headers={}
        for name,value in response['headers']:
            name=name.lower()
            if name=='date':parsedate_to_datetime(value);value='<validated-http-date>'
            if name=='content-length':
                assert int(value)==len(response['body'].encode('utf-8'))
                value='<validated-content-length>'
            headers.setdefault(name,[]).append(value)
        try:body=json.loads(response['body'])
        except json.JSONDecodeError:body=response['body']
        wire.append({'status':response['status'],'body':body,'headers':headers})
    return {'input':norm(case.get('payload')),'startup_ready':case['startup_ready'],
            'responses':wire,'before':snapshot(case['before']),'after':snapshot(case['after'])}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('baseline');parser.add_argument('candidate');parser.add_argument('output');args=parser.parse_args()
    baseline=load(args.baseline);candidate=load(args.candidate);matched=[];different=[]
    for name in sorted(baseline.keys()|candidate.keys()):
        left=canonical(baseline[name]) if name in baseline else None
        right=canonical(candidate[name]) if name in candidate else None
        if left==right and left is not None and left['startup_ready']:matched.append(name)
        else:different.append({'case':name,'different_fields':[key for key in set(left or {})|set(right or {}) if (left or {}).get(key)!=(right or {}).get(key)],'baseline':left,'candidate':right})
    result={'cases':len(matched)+len(different),'matched':len(matched),'different':len(different),'matched_cases':matched,'differences':different,
            'scope':'HTTP status/body/headers, submitted payload, original eight table relations before and after restore; candidate authorization table must remain empty'}
    Path(args.output).write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({k:result[k] for k in ['cases','matched','different']}))
    return bool(different)
if __name__=='__main__':sys.exit(main())

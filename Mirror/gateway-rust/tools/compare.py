"""Response differential with narrowly defined, validated nondeterminism. Author: MingTea.
This is not an upstream-trace, streaming or whole-product equivalence verdict.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import sys
from email.utils import parsedate_to_datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY=hashlib.sha256(b"contract-encryption-key-000000000000001").digest()


def index(records):
    out={}
    for record in records:
        if record["kind"]=="http":
            key=f"{record['method']} {record['path']} auth={record['auth']}"
        elif record["kind"]=="scenario":
            key="scenario:"+record["id"]
        elif record["kind"]=="startup":
            key="startup:"+json.dumps([record['secret'],record['input_port']])
        else:
            continue
        if key in out: raise ValueError("Duplicate observation: "+key)
        out[key]=record
    return out


def normalize(value,field="",latest_token=None):
    if isinstance(value,dict):return {k:normalize(v,k,latest_token) for k,v in value.items()}
    if isinstance(value,list):return [normalize(v,field,latest_token) for v in value]
    if field in ("created_at","updated_at","created_time","updated_time","last_check_at") and value is not None:
        if not isinstance(value,int) or value<0:raise ValueError("Invalid timestamp")
        return "<validated-unix-time>"
    if isinstance(value,str) and value.startswith("enc:v1:"):
        encrypted=base64.urlsafe_b64decode(value[7:]+"="*(-len(value[7:])%4))
        plain=AESGCM(KEY).decrypt(encrypted[:12],encrypted[12:],None).decode()
        try:plain=json.loads(plain)
        except json.JSONDecodeError:pass
        return {"original_envelope":"enc:v1:","verified_plaintext":normalize(plain,field,latest_token)}
    if field=="mirror_token" and value:
        if latest_token is None or value!="sha256:"+hashlib.sha256(latest_token.encode()).hexdigest():
            raise ValueError("Persisted mirror token is not tied to issued handoff token")
        return "<verified-issued-token-hash>"
    if field=="login_url" and isinstance(value,str):
        prefix="/api/not-login?user_gateway_token="
        if not value.startswith(prefix) or not re.fullmatch("[0-9a-f]{32,64}",value[len(prefix):]):
            raise ValueError("Invalid login handoff shape")
        return prefix+"<validated-token>"
    return value


def observed(records):
    items=index(records)
    latest=None
    handoff=items.get("scenario:handoff",{})
    for name,value in handoff.get("headers",[]):
        if name.lower()=="set-cookie" and value.startswith("mirror_token="):
            latest=value.split(";",1)[0].split("=",1)[1]
    out={}
    for key,record in items.items():
        if record["kind"]=="startup":
            out[key]={k:record[k] for k in ("exit","stdout","stderr")}
            continue
        body=record["body"]
        try:body=json.loads(body)
        except json.JSONDecodeError:pass
        result={"status":record["status"],"body":normalize(body,latest_token=latest)}
        headers={}
        for name,value in record.get("headers",[]):
            name=name.lower()
            if name=="date":
                parsedate_to_datetime(value)
                value="<validated-http-date>"
            if name=="content-length":
                if int(value)!=len(record['body'].encode()):raise ValueError("Content-Length mismatch")
                value="<verified-body-length>"
            if name=="set-cookie" and value.startswith("mirror_token="):
                token=value.split(";",1)[0].split("=",1)[1]
                if token:
                    if not re.fullmatch("[0-9a-f]{32,64}",token):raise ValueError("Invalid cookie token")
                    value=value.replace("mirror_token="+token,"mirror_token=<validated-token>",1)
            headers.setdefault(name,[]).append(value)
        if "headers" in record:result["headers"]=headers
        out[key]=result
    return out


def main():
    p=argparse.ArgumentParser();p.add_argument("baseline");p.add_argument("candidate");p.add_argument("output");a=p.parse_args()
    baseline=observed(json.loads(Path(a.baseline).read_text(encoding="utf-8")))
    candidate=observed(json.loads(Path(a.candidate).read_text(encoding="utf-8")))
    diffs=[];matched=[]
    for key in sorted(baseline.keys()|candidate.keys()):
        if baseline.get(key)==candidate.get(key):matched.append(key)
        else:diffs.append({"case":key,"baseline":baseline.get(key),"candidate":candidate.get(key)})
    result={"response_cases":len(baseline.keys()|candidate.keys()),"matched":len(matched),"different":len(diffs),
            "scope":"response status, JSON/text body, headers; no whole-product equivalence claim",
            "not_compared":["upstream traces","full schema beyond backup","SSE/WebSocket","retry timing","real TLS"],
            "matched_cases":matched,"differences":diffs}
    Path(a.output).write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding="utf-8")
    print(json.dumps({k:result[k] for k in ("response_cases","matched","different")}))
    sys.exit(1 if diffs else 0)


if __name__=="__main__":main()

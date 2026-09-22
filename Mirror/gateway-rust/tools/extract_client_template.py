"""Reconstruct a static client resource from the approved local oracle, not the executable.
Author: MingTea. Runtime gateway never reads or executes the original gateway.
"""
import hashlib
import json
from pathlib import Path

root=Path(__file__).resolve().parents[1]
source=root/'evidence/proxy-v3-original-010/results.json'
records=json.loads(source.read_text(encoding='utf-8'))
def script(case):
    body=next(row['body'] for row in records if row.get('id')==case)
    return body[body.index('<script id="gateway-user-logout-button">'):]
original=script('p1-me-html')
assert original == script('p1-me-html-bob')
assert original.replace('var forceChatMode = true;', 'var forceChatMode = false;',1)==script('p1-me-html-work-false')
assert hashlib.sha256(original.encode()).hexdigest()=='97ffff5a75fec31ea5b66f91046030a0a8017943dbbe219180631b3d52a2a8c2'
template=original.replace('var forceChatMode = true;','var forceChatMode = @@FORCE_CHAT@@;',1)
for variable,token in [('_gwBlockedPaths','@@BLOCKED_PATHS@@'),('_gwInternalUpstreamHosts','@@INTERNAL_HOSTS@@')]:
    prefix='  var '+variable+' = '
    line=next(line for line in template.splitlines() if line.startswith(prefix))
    if variable=='_gwInternalUpstreamHosts':
        hosts=json.loads(line[len(prefix):-1]);hosts.remove('127.0.0.1')
    template=template.replace(line,prefix+token+';',1)
out=root/'src/assets'
out.mkdir(exist_ok=True)
(out/'gateway-client.html').write_text(template,encoding='utf-8',newline='\n')
(out/'gateway-client-hosts.json').write_text(json.dumps(hosts,separators=(',',':')),encoding='utf-8')
manifest={'source':str(source),'case':'p1-me-html','original_resource_sha256':hashlib.sha256(original.encode()).hexdigest(),
          'template_sha256':hashlib.sha256(template.encode()).hexdigest(),
          'parameters':['force_chat_mode','blocked_paths','configured_upstream_host'],
          'validation':'HTTP resource byte comparison only; no browser execution'}
(root/'evidence/client-template-v3.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
print(json.dumps(manifest))

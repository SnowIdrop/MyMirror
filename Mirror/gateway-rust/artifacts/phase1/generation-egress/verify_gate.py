"""Run one exact synthetic Rust gate on prior/current/actually rolled-back source archives."""
from pathlib import Path
import hashlib,json,os,re,shutil,subprocess,sys,zipfile

here=Path(__file__).resolve().parent; root=here.parents[2]; phase=here.parent
events=[]
def command(args,env=None,cwd=root):
    r=subprocess.run(args,env=env,cwd=cwd,capture_output=True)
    value={'command':list(map(str,args)),'cwd':str(cwd),'exit_status':r.returncode,'stdout':r.stdout.decode('utf-8'),'stderr':r.stderr.decode('utf-8')}
    events.append(value);(here/'gate-execution.json').write_text(json.dumps(events,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    return value
with zipfile.ZipFile(here/'CANDIDATE.zip') as z: gate=z.read('tests/generation_egress.rs')
shutil.copyfile(here/'CANDIDATE.zip',here/'ROLLBACK_PREVIOUS.zip')
rollback=command(['E:/T/Git2026_6/bin/bash.exe','-c','artifacts/phase1/ROLLBACK.sh artifacts/phase1/generation-egress/ROLLBACK_PREVIOUS.zip --previous-candidate'])
assert rollback['exit_status']==0
before_sha=hashlib.sha256((here/'BASELINE_INPUT.zip').read_bytes()).hexdigest()
assert before_sha==hashlib.sha256((here/'ROLLBACK_PREVIOUS.zip').read_bytes()).hexdigest()
results=[]
for label,archive,expected in [('BASELINE_PREVIOUS','BASELINE_INPUT.zip',101),('MODIFIED','CANDIDATE.zip',0),('ROLLBACK_PREVIOUS','ROLLBACK_PREVIOUS.zip',101)]:
    source=here/('gate-'+label.lower());source.mkdir(exist_ok=True)
    with zipfile.ZipFile(here/archive) as z:
        assert z.testzip() is None;z.extractall(source)
    (source/'tests/generation_egress.rs').write_bytes(gate)
    env=os.environ.copy();env.update({'CARGO_HOME':str(root/'.build/phase1-toolchain/cargo'),'RUSTUP_HOME':str(root/'.build/phase1-toolchain/rustup'),'CARGO_TARGET_DIR':str(root/'.build/generation-egress-gates'/label.lower())})
    env['PATH']=str(Path(env['CARGO_HOME'])/'bin')+os.pathsep+env['PATH']
    result=command([str(Path(env['CARGO_HOME'])/'bin/cargo.exe'),'test','--locked','--offline','--manifest-path',str(source/'Cargo.toml'),'--test','generation_egress'],env)
    assert result['exit_status']==expected,result
    match=re.search(r'test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed',result['stdout']);assert match,result
    passed,failed=map(int,match.groups());assert (passed,failed)==((12,0) if expected==0 else (0,12))
    row={'label':label,'source_archive_sha256':hashlib.sha256((here/archive).read_bytes()).hexdigest(),'same_test_sha256':hashlib.sha256(gate).hexdigest(),'passed':passed,'failed':failed,'command_event':len(events)-1,'exit_status':result['exit_status']}
    results.append(row);print(json.dumps(row),flush=True)
(here/'GATE_RESULTS.json').write_text(json.dumps({'baseline_previous_sha256':before_sha,'rollback_previous_hash_matches':True,'same_input':True,'results':results,'scope':'synthetic 12-case library gate; rollback uses the same main ROLLBACK.sh optional previous-candidate mode; default original-source rollback remains separate','real_token_read':False},indent=2)+'\n',encoding='utf-8')

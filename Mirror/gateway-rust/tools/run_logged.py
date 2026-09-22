"""Literal stdout/stderr/exit evidence for a command array. Author: MingTea."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time

p=argparse.ArgumentParser()
p.add_argument("--output",required=True)
p.add_argument("command",nargs=argparse.REMAINDER)
a=p.parse_args()
command=a.command[1:] if a.command[:1]==["--"] else a.command
out=Path(a.output).resolve()
out.mkdir(parents=True,exist_ok=False)
start=time.time()
with (out/"stdout.txt").open("wb") as stdout,(out/"stderr.txt").open("wb") as stderr:
    process=subprocess.run(command,stdout=stdout,stderr=stderr)
result={"event":"command_execution","command":command,"cwd":str(Path.cwd()),
        "exit":process.returncode,"elapsed_seconds":time.time()-start}
(out/"command.json").write_text(json.dumps(result,indent=2),encoding="utf-8")
print(json.dumps(result))
sys.exit(process.returncode)

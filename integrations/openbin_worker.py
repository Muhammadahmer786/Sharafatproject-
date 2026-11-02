"""Run the upstream extractor inside a networkless container with RAM-backed scratch space."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def main():
    data=sys.stdin.buffer.read(10*1024*1024+1)
    if not 256<=len(data)<=10*1024*1024 or not data.startswith(b'MZ'):
        raise ValueError('Unsupported input')
    scratch=Path('/tmp/sentinel'); scratch.mkdir(mode=0o700)
    sample=scratch/'sample.exe'; sample.write_bytes(data)
    project=scratch/'project'; project.mkdir()
    output=scratch/'analysis.json'
    environment=dict(os.environ)
    environment['HOME']='/tmp'
    environment['GHIDRA_EXTRACT_DEADLINE_EPOCH']=str(time.time()+270)
    command=['/opt/ghidra/support/analyzeHeadless',str(project),'sentinel',
        '-import',str(sample),'-scriptPath','/app/scripts','-preScript','preflight.py',
        '-postScript','extract.py',str(output),'-analysisTimeoutPerFile','180',
        '-max-cpu','2','-deleteProject','-log',str(scratch/'analysis.log')]
    process=subprocess.run(command,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=300,env=environment)
    if process.returncode or not output.is_file() or output.stat().st_size>16*1024*1024:
        raise ValueError('Decompilation failed or exceeded the result limit')
    sys.stdout.buffer.write(output.read_bytes())


if __name__=='__main__':
    try:
        main()
    except Exception:
        sys.stdout.write(json.dumps({'error':'Local decompilation failed or timed out. No sample was executed or uploaded.'}))

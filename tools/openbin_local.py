"""Operator-run local decompilation. Saves code locally; makes no cloud requests."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parents[1]/'.env',override=False)
from sentinel.openbin_local import decompile_local


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file',type=Path)
    parser.add_argument('--output',type=Path,required=True,help='New local analysis JSON; never overwrites an existing file')
    args=parser.parse_args()
    if args.output.exists():
        parser.error('Output already exists. Choose a new path.')
    with args.file.open('rb') as source:
        data=source.read(10*1024*1024+1)
    result=decompile_local(data,args.file.name)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x',encoding='utf-8') as target:
        json.dump(result,target,indent=2)
    print('Local decompilation saved. No cloud upload or AI model call was made.')
    print(args.output.resolve())
    print('Review the code before importing findings. The output can contain sensitive decompiled code.')


if __name__=='__main__':
    try:
        main()
    except (ValueError,OSError) as exc:
        raise SystemExit(str(exc))

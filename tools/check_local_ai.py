"""Run the real isolated OpenBin/local-model pipeline on an authorized PE fixture."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sample', type=Path, default=ROOT / 'examples/synthetic-demo.exe')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    from dotenv import load_dotenv
    from sentinel.ai_jobs import run_pipeline
    from sentinel.local_ai import model_status
    load_dotenv(ROOT / '.env', override=False)
    config = dict(PE_WORKER_MODE='docker', PE_WORKER_IMAGE=os.getenv('PE_WORKER_IMAGE', 'sentinel-pe-worker:local'),
        OPENBIN_WORKER_IMAGE=os.getenv('OPENBIN_WORKER_IMAGE', 'sentinel-openbin-worker:local'),
        LOCAL_AI_URL=os.getenv('LOCAL_AI_URL', 'http://127.0.0.1:11434'),
        LOCAL_AI_MODEL=os.getenv('LOCAL_AI_MODEL', 'qwen3:4b'), LOCAL_AI_TIMEOUT=600)
    status = model_status(config)
    if not status['available']:
        raise SystemExit(status['message'])
    if not 256 <= args.sample.stat().st_size <= 10 * 1024 * 1024:
        raise SystemExit('Select a native PE fixture at most 10 MiB.')
    data = args.sample.read_bytes(); started = time.monotonic()
    print('Installed local model: ' + status['model'], flush=True)
    def progress(stage, milestone):
        print(f'{stage}: milestone {milestone}, elapsed {time.monotonic()-started:.1f}s', flush=True)
    result = run_pipeline(data, args.sample.name, config, threading.Event(), progress, str(uuid.uuid4()))
    exported = dict(state='complete', filename=args.sample.name, sha256=hashlib.sha256(data).hexdigest(),
                    result=result, elapsed_seconds=round(time.monotonic()-started, 2))
    with args.output.open('x', encoding='utf-8') as output:
        json.dump(exported, output, indent=2)
    print(json.dumps({key: result[key] for key in ('verdict', 'model', 'model_digest', 'ai_model_ran', 'processing_location', 'coverage')}, indent=2), flush=True)
    print(f'Completed in {exported["elapsed_seconds"]} seconds. This validates the pipeline, not detection accuracy.', flush=True)


if __name__ == '__main__':
    main()

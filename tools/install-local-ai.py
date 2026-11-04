"""Install the pinned official portable Ollama runtime in a local folder.

Run explicitly; never installs a system service or opens a firewall port.
"""
import argparse
import json
from pathlib import Path
import sys
import urllib.request
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.setup_downloads import verified_download

VERSION = '0.40.13'
URL = f'https://github.com/ollama/ollama/releases/download/v{VERSION}/ollama-windows-amd64.zip'
SHA256 = '7afa38624fa62ee5d8293422d0ab084c1bb4603134c7f4dafce11a033b57cc19'
SIZE = 1601969847


def validate_destination(directory, allow_system_drive=False):
    root = Path(directory).resolve()
    if root == root.parent or (root.drive.lower() == 'c:' and not allow_system_drive):
        raise ValueError('Choose a dedicated runtime folder; C: requires --allow-system-drive.')
    return root


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=Path('D:/SentinelRuntime/ai'))
    parser.add_argument('--allow-system-drive', action='store_true', help='Allow an explicitly selected C: runtime folder')
    args = parser.parse_args()
    try:
        root = validate_destination(args.directory, args.allow_system_drive)
    except ValueError as exc:
        parser.error(str(exc))
    root.mkdir(parents=True, exist_ok=True)
    archive = root / f'ollama-{VERSION}.zip'
    verified_download(URL, archive, SHA256, size=SIZE, min_free_gib=9)
    target = root / f'ollama-{VERSION}'
    marker = target / '.verified-source.json'
    if not marker.exists() or not (target / 'ollama.exe').is_file():
        print('Verified SHA-256. Extracting the portable runtime...', flush=True)
        with zipfile.ZipFile(archive) as bundle:
            if sum(item.file_size for item in bundle.infolist()) > 7 * 1024**3:
                raise RuntimeError('Unexpected expanded archive size.')
            for item in bundle.infolist():
                path = (target / item.filename).resolve()
                if not path.is_relative_to(target):
                    raise RuntimeError('Unsafe archive path.')
            bundle.extractall(target)
        marker.write_text(json.dumps({'version': VERSION, 'url': URL, 'sha256': SHA256}, indent=2), encoding='utf-8')
    for name in ('models', 'tmp', 'logs'):
        (root / name).mkdir(exist_ok=True)
    print(f'Local runtime installed at {target}. Run tools/start-local-ai.ps1, then pull qwen3:4b.', flush=True)


if __name__ == '__main__':
    main()

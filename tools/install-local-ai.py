"""Install the pinned official portable Ollama runtime on a data drive.

Run explicitly; never installs a system service or opens a firewall port.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import urllib.request
import zipfile

VERSION = '0.40.13'
URL = f'https://github.com/ollama/ollama/releases/download/v{VERSION}/ollama-windows-amd64.zip'
SHA256 = '7afa38624fa62ee5d8293422d0ab084c1bb4603134c7f4dafce11a033b57cc19'
SIZE = 1601969847


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=Path('D:/SentinelRuntime/ai'))
    args = parser.parse_args()
    root = args.directory.resolve()
    if root == root.parent or root.drive.lower() == 'c:':
        parser.error('Choose a dedicated folder on a data drive.')
    root.mkdir(parents=True, exist_ok=True)
    archive = root / f'ollama-{VERSION}.zip'
    if not archive.exists():
        if shutil.disk_usage(root).free < 9 * 1024**3:
            parser.error('At least 9 GiB free space is required for the runtime and model.')
        partial = archive.with_suffix('.partial')
        print('Downloading the official Ollama portable runtime...', flush=True)
        with urllib.request.urlopen(URL, timeout=60) as response, partial.open('wb') as output:
            total = 0
            while chunk := response.read(1024**2):
                total += len(chunk)
                if total > SIZE:
                    raise RuntimeError('Unexpected archive size.')
                output.write(chunk)
                if total % (64 * 1024**2) == 0:
                    print(f'Downloaded {total // 1024**2} MiB', flush=True)
        if total != SIZE:
            raise RuntimeError('Incomplete download.')
        partial.replace(archive)
    with archive.open('rb') as source:
        digest = hashlib.file_digest(source, 'sha256').hexdigest()
    if digest != SHA256:
        raise RuntimeError('Runtime checksum mismatch; nothing installed.')
    target = root / f'ollama-{VERSION}'
    marker = target / '.verified-source.json'
    if not marker.exists():
        print('Verified SHA-256. Extracting the portable runtime...', flush=True)
        with zipfile.ZipFile(archive) as bundle:
            if sum(item.file_size for item in bundle.infolist()) > 7 * 1024**3:
                raise RuntimeError('Unexpected expanded archive size.')
            for item in bundle.infolist():
                path = (target / item.filename).resolve()
                if not path.is_relative_to(target):
                    raise RuntimeError('Unsafe archive path.')
            bundle.extractall(target)
        marker.write_text(json.dumps({'version': VERSION, 'url': URL, 'sha256': digest}, indent=2), encoding='utf-8')
    for name in ('models', 'tmp', 'logs'):
        (root / name).mkdir(exist_ok=True)
    print(f'Local runtime installed at {target}. Run tools/start-local-ai.ps1, then pull qwen3:4b.', flush=True)


if __name__ == '__main__':
    main()

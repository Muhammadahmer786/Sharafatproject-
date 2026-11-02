"""Install a dedicated Docker Engine WSL distribution on a chosen data drive.

Run explicitly as the Windows account that runs Sentinel. Never reboots Windows,
unregisters a distribution, or exposes Docker over TCP. Requires network access.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import urllib.request


def fetch_json(url):
    with urllib.request.urlopen(url, timeout=30) as response:
        return json.load(response)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--distro', default='SentinelLab')
    args = parser.parse_args()
    if os.name != 'nt' or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', args.distro):
        parser.error('Use Windows and a simple dedicated distribution name.')
    destination = args.directory.resolve()
    if destination.parent == destination or destination.drive.lower() == os.environ.get('SystemDrive', 'C:').lower():
        parser.error('Choose a dedicated folder on a data drive, not the system drive or drive root.')
    if shutil.disk_usage(destination.anchor).free < 12 * 1024**3:
        parser.error('At least 12 GiB of free space is required before installation.')
    wsl = shutil.which('wsl.exe')
    if not wsl:
        parser.error('Install WSL 2 first.')
    result = subprocess.run([wsl, '--list', '--quiet'], capture_output=True, check=True)
    names = result.stdout.decode('utf-16-le').replace('\x00', '').splitlines()
    if args.distro in names:
        parser.error('Distribution already exists. Reuse it; this installer never overwrites a distribution.')
    config = Path.home() / '.wslconfig'
    if config.exists():
        parser.error('An existing .wslconfig needs operator review for data-drive swap before installation.')
    destination.mkdir(parents=True, exist_ok=True)
    downloads = destination / 'downloads'
    downloads.mkdir(exist_ok=True)
    manifest = fetch_json('https://raw.githubusercontent.com/microsoft/WSL/master/distributions/DistributionInfo.json')
    entry = next(d for d in manifest['ModernDistributions']['Ubuntu'] if d['Name'] == 'Ubuntu-24.04')['Amd64Url']
    if not entry['Url'].startswith('https://releases.ubuntu.com/') or not re.fullmatch('[a-f0-9]{64}', entry['Sha256']):
        raise RuntimeError('Unexpected Ubuntu manifest entry.')
    archive = downloads / 'ubuntu-24.04-amd64.wsl'
    if not archive.exists():
        partial = archive.with_suffix('.partial')
        print('Downloading official Ubuntu WSL archive to the data drive...', flush=True)
        with urllib.request.urlopen(entry['Url'], timeout=60) as response, partial.open('wb') as target:
            size = 0
            while chunk := response.read(1024 * 1024):
                size += len(chunk)
                if size > 2 * 1024**3:
                    raise RuntimeError('Unexpected archive size; download stopped.')
                target.write(chunk)
                if size % (32 * 1024**2) == 0:
                    print(f'Downloaded {size // 1024**2} MiB', flush=True)
        partial.replace(archive)
    with archive.open('rb') as source:
        actual = hashlib.file_digest(source, 'sha256').hexdigest()
    if actual != entry['Sha256']:
        raise RuntimeError('Ubuntu archive checksum mismatch; nothing installed.')
    (downloads / 'ubuntu-source.json').write_text(json.dumps(entry, indent=2), encoding='utf-8')
    # No existing distributions/configuration are overwritten. Swap on C: would
    # consume the remaining system-drive space on the target machine.
    with config.open('x', encoding='utf-8') as target:
        target.write('[wsl2]\nmemory=6GB\nprocessors=2\nswap=0\n')
    print('Verified Ubuntu archive. Importing dedicated WSL 2 runtime...', flush=True)
    subprocess.run([wsl, '--import', args.distro, str(destination / 'wsl'), str(archive), '--version', '2'], check=True)
    configure = b'printf "[boot]\\nsystemd=true\\n" > /etc/wsl.conf\n'
    subprocess.run([wsl, '-d', args.distro, '-u', 'root', '--exec', 'sh', '-s'], input=configure, check=True)
    subprocess.run([wsl, '--terminate', args.distro], check=True)
    script = (Path(__file__).with_name('install-docker-engine.sh')).read_bytes()
    subprocess.run([wsl, '-d', args.distro, '-u', 'root', '--exec', 'bash', '-s'], input=script, check=True)
    print(f'Local Docker runtime installed. Set SENTINEL_WSL_DISTRO={args.distro} in the private .env.', flush=True)


if __name__ == '__main__':
    main()

"""Install a dedicated Docker Engine WSL distribution on a chosen data drive.

Run explicitly as the Windows account that runs Sentinel. Never reboots Windows,
unregisters a distribution, or exposes Docker over TCP. Requires network access.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.setup_downloads import verified_download


def fetch_json(url):
    with urllib.request.urlopen(url, timeout=30) as response:
        return json.load(response)


def registered_location(distro):
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Lxss') as root:
        for index in range(winreg.QueryInfoKey(root)[0]):
            with winreg.OpenKey(root, winreg.EnumKey(root, index)) as item:
                if winreg.QueryValueEx(item, 'DistributionName')[0] == distro:
                    return Path(winreg.QueryValueEx(item, 'BasePath')[0].removeprefix('\\\\?\\'))
    return None


def validate_resume(expected, registered):
    if registered is None or Path(expected).resolve() != Path(registered).resolve():
        raise ValueError('The existing distribution belongs to a different location; it was not changed.')


def systemd_config(original):
    lines = original.splitlines(keepends=True)
    boot = None
    in_boot = False
    found = False
    for index, line in enumerate(lines):
        section = re.fullmatch(r'\s*\[([^]]+)\]\s*', line.strip())
        if section:
            in_boot = section[1].lower() == 'boot'
            if in_boot:
                boot = index
        elif in_boot and re.match(r'\s*systemd\s*=', line):
            lines[index] = 'systemd=true\n'
            found = True
    if not found:
        if boot is None:
            return original.rstrip('\r\n') + ('\n' if original else '') + '[boot]\nsystemd=true\n'
        if not lines[boot].endswith('\n'):
            lines[boot] += '\n'
        lines.insert(boot + 1, 'systemd=true\n')
    return ''.join(lines)


def enable_systemd(wsl, distro):
    command = [wsl, '-d', distro, '-u', 'root', '--exec']
    current = subprocess.run([*command, 'sh', '-c', 'if [ -f /etc/wsl.conf ]; then cat /etc/wsl.conf; fi'],
                             capture_output=True, check=True, timeout=60).stdout.decode('utf-8')
    updated = systemd_config(current)
    if updated != current:
        subprocess.run([*command, 'sh', '-c', 'cat > /etc/wsl.conf'], input=updated.encode('utf-8'), check=True)
    subprocess.run([wsl, '--terminate', distro], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--distro', default='SentinelLab')
    parser.add_argument('--allow-system-drive', action='store_true')
    parser.add_argument('--preserve-wsl-config', action='store_true', help='Do not create or change global .wslconfig')
    parser.add_argument('--resume', action='store_true', help='Resume only a distro registered at this exact runtime location')
    args = parser.parse_args()
    if os.name != 'nt' or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', args.distro):
        parser.error('Use Windows and a simple dedicated distribution name.')
    destination = args.directory.resolve()
    if destination.parent == destination or (not args.allow_system_drive and destination.drive.lower() == os.environ.get('SystemDrive', 'C:').lower()):
        parser.error('Choose a dedicated folder on a data drive, not the system drive or drive root.')
    wsl = shutil.which('wsl.exe')
    if not wsl:
        parser.error('Install WSL 2 first.')
    result = subprocess.run([wsl, '--list', '--quiet'], capture_output=True, check=True)
    names = result.stdout.decode('utf-16-le').replace('\x00', '').splitlines()
    existing = args.distro in names
    if existing:
        if not args.resume:
            parser.error('Distribution already exists. Reuse it; this installer never overwrites a distribution.')
        try:
            validate_resume(destination / 'wsl', registered_location(args.distro))
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
    elif shutil.disk_usage(destination.anchor).free < 12 * 1024**3:
        parser.error('At least 12 GiB of free space is required before installation.')
    config = Path.home() / '.wslconfig'
    if config.exists() and not args.preserve_wsl_config:
        parser.error('An existing .wslconfig needs operator review for data-drive swap before installation.')
    if existing:
        os_release = subprocess.check_output([wsl, '-d', args.distro, '-u', 'root', '--exec', 'cat', '/etc/os-release'], timeout=60).decode()
        if 'ID=ubuntu' not in os_release or 'VERSION_ID="24.04"' not in os_release:
            parser.error('Resume requires the dedicated Ubuntu 24.04 distribution.')
        enable_systemd(wsl, args.distro)
        script = (Path(__file__).with_name('install-docker-engine.sh')).read_bytes()
        subprocess.run([wsl, '-d', args.distro, '-u', 'root', '--exec', 'bash', '-s'], input=script, check=True)
        print('Dedicated Docker installation resumed successfully.')
        return
    destination.mkdir(parents=True, exist_ok=True)
    downloads = destination / 'downloads'
    downloads.mkdir(exist_ok=True)
    manifest = fetch_json('https://raw.githubusercontent.com/microsoft/WSL/master/distributions/DistributionInfo.json')
    entry = next(d for d in manifest['ModernDistributions']['Ubuntu'] if d['Name'] == 'Ubuntu-24.04')['Amd64Url']
    if not entry['Url'].startswith('https://releases.ubuntu.com/') or not re.fullmatch('[a-f0-9]{64}', entry['Sha256']):
        raise RuntimeError('Unexpected Ubuntu manifest entry.')
    archive = downloads / 'ubuntu-24.04-amd64.wsl'
    verified_download(entry['Url'], archive, entry['Sha256'], min_free_gib=12)
    (downloads / 'ubuntu-source.json').write_text(json.dumps(entry, indent=2), encoding='utf-8')
    # No existing distributions/configuration are overwritten. Swap on C: would
    # consume the remaining system-drive space on the target machine.
    if not args.preserve_wsl_config:
        with config.open('x', encoding='utf-8') as target:
            target.write('[wsl2]\nmemory=6GB\nprocessors=2\nswap=0\n')
    print('Verified Ubuntu archive. Importing dedicated WSL 2 runtime...', flush=True)
    subprocess.run([wsl, '--import', args.distro, str(destination / 'wsl'), str(archive), '--version', '2'], check=True)
    enable_systemd(wsl, args.distro)
    script = (Path(__file__).with_name('install-docker-engine.sh')).read_bytes()
    subprocess.run([wsl, '-d', args.distro, '-u', 'root', '--exec', 'bash', '-s'], input=script, check=True)
    print(f'Local Docker runtime installed. Set SENTINEL_WSL_DISTRO={args.distro} in the private .env.', flush=True)


if __name__ == '__main__':
    main()

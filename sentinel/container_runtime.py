"""Explicit Docker transport; WSL receives binary pipes without a shell wrapper."""
import os
import re
import shutil


def docker_command():
    distro = os.getenv('SENTINEL_WSL_DISTRO', '').strip()
    if distro:
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', distro):
            raise ValueError('Configure a valid dedicated WSL distribution name.')
        wsl = shutil.which('wsl.exe')
        if not wsl:
            raise ValueError('The configured WSL Docker runtime is unavailable. Check the local worker setup.')
        return [wsl, '-d', distro, '-u', 'root', '--exec', 'docker']
    docker = shutil.which('docker')
    if not docker:
        raise ValueError('Docker is required for isolated processing. Complete the local worker setup first.')
    return [docker]


def worker_timeout(command,seconds):
    # A stopped WSL VM took 14 seconds to boot on the target workstation.
    # Keep the processing deadline and allow a separate bounded startup margin.
    return seconds+30 if '--exec' in command else seconds

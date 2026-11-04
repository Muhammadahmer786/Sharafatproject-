"""Verified installer assets: never publish incomplete/unverified downloads."""
import hashlib
from pathlib import Path
import shutil
import urllib.request
import uuid


def verified_download(url, target, digest, *, size=None, maximum=2 * 1024**3, min_free_gib=0):
    target = Path(target)
    partial = target.with_suffix(target.suffix + '.partial')
    if target.is_symlink() or partial.is_symlink():
        raise ValueError('Installer cache files must not be symbolic links.')
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        with target.open('rb') as source:
            valid = hashlib.file_digest(source, 'sha256').hexdigest() == digest
        if valid and (size is None or target.stat().st_size == size):
            return target
        rejected = target.with_name(target.name + '.rejected-' + uuid.uuid4().hex[:12])
        target.rename(rejected)
        print(f'Invalid cached download retained as {rejected.name}; downloading a verified replacement.', flush=True)
    if shutil.disk_usage(target.parent).free < min_free_gib * 1024**3:
        raise RuntimeError(f'At least {min_free_gib} GiB free is needed before downloading this runtime.')
    checksum = hashlib.sha256()
    total = 0
    print(f'Downloading {target.name}...', flush=True)
    with urllib.request.urlopen(url, timeout=60) as response, partial.open('wb') as output:
        while chunk := response.read(1024**2):
            total += len(chunk)
            if total > (size if size is not None else maximum):
                raise RuntimeError('Unexpected archive size; download was not installed.')
            output.write(chunk)
            checksum.update(chunk)
            if total % (64 * 1024**2) == 0:
                print(f'Downloaded {total // 1024**2} MiB', flush=True)
    if size is not None and total != size:
        raise RuntimeError('Incomplete download; rerun setup to download this asset again.')
    if checksum.hexdigest() != digest:
        rejected = partial.with_name(target.name + '.rejected-' + uuid.uuid4().hex[:12])
        partial.rename(rejected)
        raise RuntimeError('Runtime checksum mismatch; nothing installed. Rerun to download a fresh copy.')
    partial.replace(target)
    return target

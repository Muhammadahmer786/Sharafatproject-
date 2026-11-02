"""Build local workers using direct Docker or the explicitly configured WSL engine."""
import argparse
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import time
import http.client
import urllib.error
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from dotenv import load_dotenv
from sentinel.container_runtime import docker_command

ARCHIVE_URL='https://github.com/openbin-ai/platform/releases/download/openbin-v0.10.0/ghidra-worker.tar.gz'
ARCHIVE_SHA256='5db065717451ae758bbd9f3302b6f4ac9c471acab23cb177780e4eb17a4dee1f'
ARCHIVE_SIZE=663034322


def download_verified(url,target,size,digest):
    """Resume bounded HTTP ranges, publishing a cache file only after verification."""
    partial=target.with_suffix('.partial')
    if target.exists():
        with target.open('rb') as source:
            actual=hashlib.file_digest(source,'sha256').hexdigest()
        if target.stat().st_size==size and actual==digest:
            return target
        if target.stat().st_size<size and not partial.exists():
            target.rename(partial)
        else:
            raise ValueError('Cached archive checksum mismatch; no image was loaded.')
    offset=partial.stat().st_size if partial.exists() else 0
    if offset>size:
        raise ValueError('Unexpected partial archive size.')
    failures=0
    while offset<size:
        end=min(offset+32*1024**2,size)-1
        request=urllib.request.Request(url,headers={'Range':f'bytes={offset}-{end}','Accept-Encoding':'identity'})
        before=offset
        try:
            with urllib.request.urlopen(request,timeout=60) as response:
                if response.status!=206 or response.headers.get('Content-Range')!=f'bytes {offset}-{end}/{size}':
                    raise ValueError('Server did not honor the bounded archive range; download stopped.')
                with partial.open('ab') as destination:
                    while offset<=end:
                        chunk=response.read1(min(1024**2,end-offset+1))
                        if not chunk:
                            break
                        destination.write(chunk)
                        offset+=len(chunk)
        except (OSError,urllib.error.URLError,http.client.HTTPException):
            # Bytes already received remain on the data drive for a bounded retry.
            pass
        if offset<=end:
            failures+=1
            if failures>=5:
                raise ValueError('Download interrupted repeatedly; rerun setup to resume the partial archive.')
            time.sleep(min(failures,3))
        else:
            failures=0
        if offset>before:
            print(f'OpenBin download: {offset//1024**2} / {size//1024**2} MiB',flush=True)
    with partial.open('rb') as source:
        actual=hashlib.file_digest(source,'sha256').hexdigest()
    if actual!=digest:
        raise ValueError('Downloaded archive checksum mismatch; no image was loaded.')
    partial.replace(target)
    return target


def download_openbin(directory):
    directory.mkdir(parents=True,exist_ok=True)
    archive=directory/'ghidra-worker-openbin-v0.10.0.tar.gz'
    if shutil.disk_usage(directory).free < 6*1024**3:
        raise ValueError('Choose a cache drive with at least 6 GiB free for the archive and worker images.')
    download_verified(ARCHIVE_URL,archive,ARCHIVE_SIZE,ARCHIVE_SHA256)
    print('OpenBin archive matches the official release SHA-256.',flush=True)
    return archive.resolve()


def engine_path(command,path):
    if '--exec' in command:
        return subprocess.check_output([*command[:-1],'wslpath','-a','-u',str(path.resolve())],timeout=30).decode().strip()
    return str(path.resolve())


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--include-openbin',action='store_true')
    parser.add_argument('--download-only',action='store_true')
    parser.add_argument('--cache-directory',type=Path,default=ROOT/'vendor')
    args=parser.parse_args()
    load_dotenv(ROOT/'.env',override=False)
    archive=download_openbin(args.cache_directory) if args.include_openbin else None
    if args.download_only:
        return
    command=docker_command()
    subprocess.run([*command,'info','--format','{{.OSType}}'],check=True)
    context=engine_path(command,ROOT)
    subprocess.run([*command,'build','--pull','-f',engine_path(command,ROOT/'Dockerfile'),
                    '-t','sentinel-pe-worker:local',context],check=True)
    if archive:
        subprocess.run([*command,'load','-i',engine_path(command,archive)],check=True)
        subprocess.run([*command,'image','inspect','openbin/ghidra-worker:7','--format','{{.Id}}'],check=True)
        subprocess.run([*command,'build','--pull=false','-f',engine_path(command,ROOT/'ghidra.Dockerfile'),
                        '-t','sentinel-openbin-worker:local',context],check=True)
    print('Images built. Run tools/check_workers.py --include-openbin for real acceptance checks.',flush=True)


if __name__=='__main__':
    main()

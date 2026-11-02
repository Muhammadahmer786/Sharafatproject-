"""Build a source-only handoff archive from an explicit allowlist."""
from pathlib import Path
import hashlib
import zipfile

root=Path(__file__).resolve().parents[1]
target=root/"artifacts"/"Sentinel-Lab-Local-Source.zip"
target.parent.mkdir(exist_ok=True)
top=["README.md","requirements.txt","requirements.lock.txt","pytest.ini","run.py","start.ps1",
     "Dockerfile","ghidra.Dockerfile","compose.yaml",".dockerignore",".env.example",".gitignore",".gitattributes"]
files=[root/name for name in top]
allowed={"sentinel":{'.py','.html','.css','.js'},"tests":{'.py','.cjs'},"tools":{'.py','.ps1','.sh'},"integrations":{'.py'},
         "docs":{'.md','.pdf'},"examples":{'.md','.json','.png','.txt','.exe'}}
for folder,suffixes in allowed.items():
    files.extend(path for path in (root/folder).rglob('*') if path.is_file()
                 and path.suffix.lower() in suffixes and '__pycache__' not in path.parts)
for path in files:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f'Missing or unsafe package input: {path.name}')
with zipfile.ZipFile(target,'w',zipfile.ZIP_DEFLATED) as archive:
    for path in sorted(files):
        archive.write(path,Path('sentinel-lab')/path.relative_to(root))
with zipfile.ZipFile(target) as archive:
    assert archive.testzip() is None
    names=archive.namelist()
    assert all(not any(part in {'.venv','instance','artifacts','__pycache__'} for part in Path(name).parts) for name in names)
    assert all(not name.lower().endswith(('.pem','.key','.db','.sqlite','.sqlite3','/.env')) for name in names)
checksum=hashlib.sha256(target.read_bytes()).hexdigest()
target.with_suffix('.zip.sha256').write_text(checksum+'  '+target.name+'\n',encoding='ascii')
print(f'Packaged {len(files)} source files; archive integrity and exclusions passed.')
print(f'Archive: {target}')
print(f'SHA-256: {checksum}')

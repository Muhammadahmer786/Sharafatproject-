"""Prompt privately for a VirusTotal key and save it in the ignored local .env file."""
from pathlib import Path
from getpass import getpass
from dotenv import set_key

root=Path(__file__).resolve().parents[1]
target=root/'.env'
if target.is_symlink():
    raise SystemExit('Refusing a symlink environment file.')
key=getpass('VirusTotal API key (hidden; empty cancels): ').strip()
if not key:
    raise SystemExit('Canceled; nothing changed.')
if len(key)>512 or any(c.isspace() for c in key):
    raise SystemExit('Invalid API key format.')
set_key(str(target),'VIRUSTOTAL_API_KEY',key)
if __import__('os').name!='nt':
    target.chmod(0o600)
print('Saved VIRUSTOTAL_API_KEY to the local .env. Restart the server to use it.')
print('On Windows, run tools/secure-local-files.ps1 to restrict its file permissions.')

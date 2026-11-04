"""Standard-library primitives for the client installer (no application imports)."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


class SetupError(RuntimeError):
    """An actionable setup failure, safe to show without a traceback."""


class RestartRequired(SetupError):
    pass


def fingerprint(paths):
    digest = hashlib.sha256()
    for path in paths:
        path = Path(path)
        digest.update(path.name.encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def locked_versions_match(lock_file, version_lookup=None):
    from importlib.metadata import PackageNotFoundError, version
    lookup = version_lookup or version
    for line in Path(lock_file).read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line.count('==') != 1:
            raise SetupError('The automatic installer requires exact name==version dependency pins.')
        name, wanted = line.split('==')
        try:
            if lookup(name.strip()) != wanted.strip():
                return False
        except PackageNotFoundError:
            return False
    return True


def prepare_env(root):
    """Copy the public template once, without guessing a lost instance secret."""
    root = Path(root)
    target = root / '.env'
    if target.is_symlink():
        raise SetupError('The .env file must not be a symbolic link.')
    if target.exists():
        return False
    database = root / 'instance/sentinel.db'
    if database.exists() and database.stat().st_size:
        raise SetupError('Existing database found without .env. Restore the original private configuration first.')
    with target.open('x', encoding='utf-8') as output:
        output.write((root / '.env.example').read_text(encoding='utf-8'))
    return True


def validate_runtime(path):
    path = Path(path).expanduser()
    if not path.is_absolute() or path == path.parent or str(path).startswith('\\\\'):
        raise SetupError('Choose an absolute local runtime folder, not a drive root or network share.')
    if path.is_symlink():
        raise SetupError('The runtime folder must not be a symbolic link.')
    return path.resolve()


class State:
    """Checkpoints hold content digests only; errors and credentials are not logged."""
    def __init__(self, path):
        self.path = Path(path)
        self.data = {'version': 1, 'completed': {}}
        if self.path.exists():
            try:
                self.data = json.loads(self.path.read_text(encoding='utf-8'))
                assert self.data['version'] == 1 and isinstance(self.data['completed'], dict)
                assert all(isinstance(k, str) and isinstance(v, str) for k, v in self.data['completed'].items())
            except (OSError, ValueError, KeyError, AssertionError, TypeError) as exc:
                raise SetupError('Invalid setup checkpoint. Preserve it and inspect instance/setup-state.json.') from exc

    def completed(self, name, digest):
        return self.data['completed'].get(name) == digest

    def stage(self, name, digest, probe, install):
        if self.completed(name, digest) and probe():
            print(f'  {name}: already checked.', flush=True)
            return
        print(f'  {name}: preparing...', flush=True)
        install()
        if not probe():
            raise SetupError(f'{name}: verification failed. Fix the reported issue and run setup again.')
        self.data['completed'][name] = digest
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix('.tmp')
        temporary.write_text(json.dumps(self.data, indent=2) + '\n', encoding='utf-8')
        temporary.replace(self.path)


class Commands:
    def __init__(self, root, environment=None):
        self.root = Path(root)
        self.environment = dict(os.environ if environment is None else environment)

    def run(self, args, *, capture=False, check=True, timeout=None, input=None, encoding='utf-8'):
        try:
            result = subprocess.run([str(arg) for arg in args], cwd=self.root,
                env=self.environment, capture_output=capture, text=True, encoding=encoding,
                errors='replace', timeout=timeout, input=input,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0) if capture else 0)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SetupError('A setup command could not finish. Check installed tools, connectivity and the error above; rerun setup.') from exc
        if check and result.returncode:
            # Arguments/output might include private prompt responses: never persist them.
            raise SetupError(f'The current setup step exited with code {result.returncode}. Resolve its error and run setup again.')
        return result

    def powershell(self, script, *args, **kwargs):
        executable = shutil.which('powershell.exe')
        if not executable:
            raise SetupError('Windows PowerShell is unavailable on this computer.')
        # This invocation applies only to trusted scripts shipped with this project;
        # it does not change user/machine policy or override organization policy.
        return self.run([executable, '-NoProfile', '-ExecutionPolicy', 'Bypass',
                         '-File', self.root / script, *args], **kwargs)


@contextmanager
def file_lock(path, *, existing_only=False):
    path = Path(path)
    if existing_only and not path.exists():
        yield
        return
    if not existing_only:
        path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open('r+b' if existing_only else 'a+b')
    try:
        if not path.stat().st_size:
            handle.write(b'0')
            handle.flush()
        handle.seek(0)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise SetupError('The server or another setup is running. Stop it before running setup again.') from exc
        yield
    finally:
        handle.close()


def require_free(path, gib):
    current = Path(path)
    while not current.exists():
        current = current.parent
    if shutil.disk_usage(current).free < gib * 1024**3:
        raise SetupError(f'At least {gib} GiB free is needed at {current}. Free space or select --runtime-directory on another local disk.')

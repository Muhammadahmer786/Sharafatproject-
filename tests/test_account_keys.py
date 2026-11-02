"""Assigned keys must survive sessions and remain bound to their owner."""
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
import sqlite3
import pytest
from cryptography.hazmat.primitives import serialization
from sentinel.models import db, User


def add_account(email):
    account = User(name='Key owner', email=email)
    account.set_password('Assigned-keys-testing-2026!')
    db.session.add(account)
    db.session.commit()
    return account


def test_assigned_keys_are_encrypted_unique_and_stable(app):
    from sentinel.account_keys import ensure_account_key, vault_passphrase
    from sentinel.models import AccountKey
    with app.app_context():
        alice = add_account('alice@example.test')
        first = ensure_account_key(alice)
        db.session.commit()
        fingerprint, private_pem = first.fingerprint, first.private_pem
        assert 'BEGIN ENCRYPTED PRIVATE KEY' in private_pem
        with pytest.raises(TypeError):
            serialization.load_pem_private_key(private_pem.encode(), password=None)
        private = serialization.load_pem_private_key(private_pem.encode(), vault_passphrase(alice.id).encode())
        public = serialization.load_pem_public_key(first.public_pem.encode())
        assert private.key_size == 3072
        assert private.public_key().public_numbers() == public.public_numbers()
        db.session.expire_all()
        assert ensure_account_key(alice).fingerprint == fingerprint
        assert ensure_account_key(alice).private_pem == private_pem
        bob = add_account('bob@example.test')
        second = ensure_account_key(bob)
        db.session.commit()
        assert second.public_pem != first.public_pem
        with pytest.raises(ValueError):
            serialization.load_pem_private_key(private_pem.encode(), vault_passphrase(bob.id).encode())
        assert db.session.query(AccountKey).count() == 2


def test_export_reencrypts_same_assigned_key_and_rejects_wrong_binding(app):
    from sentinel.account_keys import ensure_account_key, vault_passphrase
    from sentinel.processing import document_operation
    with app.app_context():
        user = add_account('export@example.test')
        key = ensure_account_key(user)
        db.session.commit()
        args = [key.private_pem.encode(), vault_passphrase(user.id), 'Owner-export-passphrase-2026!', key.public_pem.encode()]
        public, exported = document_operation('export_keys', args, mode='native-worker')
        private = serialization.load_pem_private_key(exported, b'Owner-export-passphrase-2026!')
        assert private.public_key().public_numbers() == serialization.load_pem_public_key(public).public_numbers()
        with pytest.raises(ValueError):
            serialization.load_pem_private_key(exported, vault_passphrase(user.id).encode())
        bob = add_account('other-export@example.test')
        other = ensure_account_key(bob)
        with pytest.raises(ValueError, match='key'):
            document_operation('export_keys', [*args[:3], other.public_pem.encode()], mode='native')
        with pytest.raises(ValueError):
            document_operation('export_keys', [args[0], args[1], 'short', args[3]], mode='native')


def test_assignment_rolls_back_with_its_account(app):
    from sentinel.account_keys import ensure_account_key
    from sentinel.models import AccountKey
    with app.app_context():
        account = User(name='Rolled back', email='rollback@example.test')
        account.set_password('Rollback-testing-2026!')
        db.session.add(account)
        ensure_account_key(account)
        db.session.rollback()
        assert db.session.query(User).count() == 0
        assert db.session.query(AccountKey).count() == 0


def test_concurrent_assignment_keeps_one_usable_key(app, monkeypatch):
    import sentinel.account_keys as vault
    from sentinel.models import AccountKey
    with app.app_context():
        identity = add_account('race@example.test').id
    actual = vault.document_operation
    barrier = Barrier(2)
    def generate_together(*args, **kwargs):
        result = actual(*args, **kwargs)
        barrier.wait(timeout=20)
        return result
    monkeypatch.setattr(vault, 'document_operation', generate_together)
    def assign(_):
        with app.app_context():
            key = vault.ensure_account_key(db.session.get(User, identity))
            db.session.commit()
            return key.public_pem
    with ThreadPoolExecutor(max_workers=2) as pool:
        public_keys = list(pool.map(assign, range(2)))
    assert public_keys[0] == public_keys[1]
    with app.app_context():
        assert db.session.query(AccountKey).count() == 1
        stored = db.session.get(AccountKey, identity)
        private = serialization.load_pem_private_key(stored.private_pem.encode(), vault.vault_passphrase(identity).encode())
        assert private.public_key().public_numbers() == serialization.load_pem_public_key(public_keys[0].encode()).public_numbers()


def test_changed_secret_cannot_unlock_or_replace_an_assigned_key(app):
    from sentinel.account_keys import ensure_account_key, vault_passphrase
    from sentinel.processing import document_operation
    with app.app_context():
        user = add_account('secret@example.test')
        key = ensure_account_key(user)
        db.session.commit()
        original = key.private_pem
        app.secret_key = 'a-different-server-secret-which-cannot-unlock-the-vault'
        same = ensure_account_key(user)
        assert same.private_pem == original
        with pytest.raises(ValueError):
            document_operation('export_keys', [same.private_pem.encode(), vault_passphrase(user.id),
                'Strong-export-passphrase-2026!', same.public_pem.encode()], mode='native')


def make_schema_three(path):
    with sqlite3.connect(path) as connection:
        connection.execute('DROP TABLE IF EXISTS account_key')
        columns = {row[1] for row in connection.execute('PRAGMA table_info(audit_event)')}
        if 'target_user_id' in columns:
            connection.execute('CREATE TABLE legacy_audit (id INTEGER PRIMARY KEY, user_id VARCHAR(36) NOT NULL REFERENCES user(id), action VARCHAR(100) NOT NULL, created_at DATETIME NOT NULL)')
            connection.execute('INSERT INTO legacy_audit SELECT id,user_id,action,created_at FROM audit_event')
            connection.execute('DROP TABLE audit_event')
            connection.execute('ALTER TABLE legacy_audit RENAME TO audit_event')
            connection.execute('CREATE INDEX ix_audit_event_user_id ON audit_event(user_id)')
        connection.execute('UPDATE schema_version SET version=3')


def test_schema_three_upgrade_preserves_user_and_adds_vault(app, tmp_path):
    from sentinel import create_app
    from sentinel.models import AccountKey, SchemaVersion
    with app.app_context():
        identity = add_account('legacy-vault@example.test').id
        db.session.remove(); db.engine.dispose()
    make_schema_three(tmp_path / 'test.db')
    upgraded = create_app(dict(app.config, INSTANCE_PATH=str(tmp_path)))
    with upgraded.app_context():
        assert db.session.get(User, identity).email == 'legacy-vault@example.test'
        assert db.session.get(SchemaVersion, 1).version == 5
        assert db.session.query(AccountKey).count() == 0
        db.session.remove(); db.engine.dispose()


def test_schema_three_restore_upgrades_only_staging_copy(app, tmp_path):
    from sentinel.models import AccountKey, SchemaVersion
    from sentinel.database import sqlite_backup
    from sentinel.operations import restore_database
    with app.app_context():
        identity = add_account('restore-vault@example.test').id
        db.session.remove(); db.engine.dispose()
    source = tmp_path / 'test.db'
    backup = sqlite_backup(source, tmp_path / 'backups')
    make_schema_three(backup)
    restore_database(backup, source, tmp_path)
    with sqlite3.connect(backup) as connection:
        assert connection.execute('SELECT version FROM schema_version').fetchone()[0] == 3
        assert 'account_key' not in {r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    with app.app_context():
        assert db.session.get(User, identity).email == 'restore-vault@example.test'
        assert db.session.get(SchemaVersion, 1).version == 5
        assert db.session.query(AccountKey).count() == 0


def test_current_backup_restores_same_encrypted_assigned_key(app,tmp_path):
    from sentinel.account_keys import ensure_account_key,vault_passphrase
    from sentinel.database import sqlite_backup
    from sentinel.operations import restore_database
    from sentinel.models import AccountKey
    with app.app_context():
        user=add_account('backup-keys@example.test')
        key=ensure_account_key(user); db.session.commit()
        identity=user.id; public=key.public_pem; encrypted=key.private_pem
        db.session.remove(); db.engine.dispose()
    source=tmp_path/'test.db'
    backup=sqlite_backup(source,tmp_path/'backups')
    restore_database(backup,source,tmp_path)
    with app.app_context():
        key=db.session.get(AccountKey,identity)
        assert (key.public_pem,key.private_pem)==(public,encrypted)
        private=serialization.load_pem_private_key(encrypted.encode(),vault_passphrase(identity).encode())
        assert private.public_key().public_numbers()==serialization.load_pem_public_key(public.encode()).public_numbers()

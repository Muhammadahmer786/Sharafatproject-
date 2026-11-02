import argparse
import getpass
import json
from pathlib import Path
from sentinel import create_app

def main():
    parser=argparse.ArgumentParser(description="Sentinel Lab local server and operator console")
    parser.add_argument("command",nargs="?",default="serve",choices=["serve","create-admin","create-user","reset-password","reset-mfa","backup","restore","doctor","migrate"])
    parser.add_argument("--port",type=int,default=5050)
    parser.add_argument('--email',help='Account identifier; passwords are always entered privately')
    parser.add_argument('--backup',help='Backup file for an offline restore')
    parser.add_argument('--confirm-restore',action='store_true',help='Confirm replacing current metadata with the selected backup')
    args=parser.parse_args()
    from sentinel.operations import server_lock, restore_database
    instance=Path(__file__).resolve().parent/'instance'
    if args.command=='serve':
        with server_lock(instance):
            serve_local(create_app(),args.port)
        return
    if args.command=='restore':
        if not args.backup or not args.confirm_restore:
            parser.error('Restore requires --backup PATH --confirm-restore. Stop the server first.')
        import os
        from dotenv import load_dotenv
        from sqlalchemy.engine import make_url
        load_dotenv(Path(__file__).resolve().parent/'.env',override=False)
        url=make_url(os.getenv('DATABASE_URL','sqlite:///'+str(instance/'sentinel.db')))
        if url.get_backend_name()!='sqlite':
            parser.error('Use your database-native restore procedure for MySQL.')
        restore_database(args.backup,url.database,instance)
        print('Database restored. Previous live data was backed up; sessions and recovery tokens were revoked.')
        return
    if args.command=='migrate':
        with server_lock(instance):
            create_app()
        print('Database schema is current. Existing data was preserved.')
        return
    app=create_app()
    if args.command in ('create-admin','create-user'):
        from sentinel.auth import valid_identity
        from sentinel.models import db,User
        email=(args.email or input('Account email: ')).strip().lower()
        name=input('Account name: ').strip()
        password=getpass.getpass("Password (12+ characters): ")
        confirm=getpass.getpass("Confirm password: ")
        if password!=confirm or not valid_identity(name,email,password):
            raise SystemExit("Invalid identity or password mismatch.")
        with app.app_context():
            if db.session.execute(db.select(User).where(User.email==email)).scalar_one_or_none():
                raise SystemExit('That email already exists; use account recovery instead.')
            user=User(name=name,email=email,role='admin' if args.command=='create-admin' else 'user')
            user.set_password(password)
            db.session.add(user)
            try:
                from sentinel.account_keys import ensure_account_key
                ensure_account_key(user)
            except ValueError as exc:
                db.session.rollback()
                raise SystemExit('Account was not created: '+str(exc)) from exc
            db.session.commit()
        print('Account and personal encryption keys created. Administrators must enroll an authenticator in Account security.')
    elif args.command in ('reset-password','reset-mfa'):
        from sentinel.models import db,User,audit
        from sentinel.security import issue_reset_token
        email=(args.email or input('Account email: ')).strip().lower()
        with app.app_context():
            user=db.session.execute(db.select(User).where(User.email==email)).scalar_one_or_none()
            if not user or not user.enabled:
                raise SystemExit('Enabled account not found.')
            if args.command=='reset-password':
                print('One-time recovery code (expires in 30 minutes): '+issue_reset_token(user))
                print('Enter it at http://127.0.0.1:5050/reset-password. Do not save it in logs.')
            else:
                if input('Verify the account owner, then type RESET MFA to continue: ')!='RESET MFA':
                    raise SystemExit('Canceled.')
                user.totp_secret=None; user.totp_pending=None; user.totp_last_step=-1
                user.revoke_sessions()
                audit(user.id,'Authenticator reset by local operator'); db.session.commit()
                print('Authenticator removed; all sessions revoked. Enroll again after signing in.')
    elif args.command=='backup':
        from sentinel.models import db
        from sentinel.database import sqlite_backup
        with app.app_context():
            if db.engine.dialect.name!='sqlite':
                raise SystemExit('Use your database-native backup procedure for MySQL.')
            print(sqlite_backup(db.engine.url.database,instance/'backups'))
        print('Keep the original instance secret separately backed up; it unlocks authenticator data and encrypted account-key vaults.')
    elif args.command=='doctor':
        from sentinel.operations import readiness
        with app.app_context():
            result=readiness(app)
            print(json.dumps(result,indent=2))
            raise SystemExit(0 if result['status']=='ready' else 1)


def serve_local(app,port):
    from contextlib import ExitStack
    from waitress import serve
    from sentinel.jobs import start_worker
    from sentinel.operations import configure_logging,backup_if_due
    configure_logging(app)
    backup_if_due(app)
    from sentinel.ai_runtime import LocalAIRuntime
    ai_runtime=LocalAIRuntime(app.config)
    ai_worker=app.extensions['local_ai_jobs']
    with ExitStack() as cleanup:
        cleanup.callback(ai_runtime.stop)
        ai_runtime.start()
        stop,worker=start_worker(app)
        cleanup.callback(worker.join,timeout=20)
        cleanup.callback(stop.set)
        cleanup.callback(ai_worker.stop)
        ai_worker.start()
        print(f'Sentinel Lab is available at http://127.0.0.1:{port}',flush=True)
        serve(app,host='127.0.0.1',port=port,threads=4,connection_limit=32,
              channel_timeout=60,cleanup_interval=10,max_request_body_size=app.config['MAX_CONTENT_LENGTH'],
              max_request_header_size=16384,inbuf_overflow=32*1024*1024,outbuf_overflow=64*1024*1024)

if __name__=="__main__":
    main()

"""Run the classroom and provision an administrator without public role selection."""
import argparse
import getpass
import json
import re
import secrets
import os
import sqlite3
import time
from pathlib import Path

from werkzeug.security import generate_password_hash

from classroom import create_app
from security_app.app import db
from security_app.mail import deliver
from security_app.settings import save_settings


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest='command', required=True)
    serve = commands.add_parser('serve')
    serve.add_argument('--port', type=int, default=5001)
    admin = commands.add_parser('create-admin')
    admin.add_argument('--email', required=True)
    mail = commands.add_parser('mail')
    mail.add_argument('--watch', action='store_true')
    commands.add_parser('doctor')
    commands.add_parser('init-db')
    commands.add_parser('configure-email')
    commands.add_parser('init-sensor')
    backup = commands.add_parser('backup')
    backup.add_argument('--output', required=True)
    geo = commands.add_parser('configure-location')
    geo.add_argument('--database', required=True)
    args = parser.parse_args()
    app = create_app({'INIT_DATABASE': True} if args.command == 'init-db' else None)
    if args.command == 'backup':
        if app.config.get('DATABASE_URL'):
            parser.error('Use your PostgreSQL provider backup or pg_dump; SQLite backup is local-only')
        target = Path(args.output).resolve()
        # Never overwrite a database or previous backup. Use SQLite's online backup API,
        # not a raw copy of a live database with a separate WAL file.
        descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        with app.app_context(), sqlite3.connect(target) as destination:
            db().backup(destination)
        print('Database backup created. It contains private account and alert records; protect it.')
    elif args.command == 'init-db':
        print('Database schema initialized. Existing records were preserved.')
    elif args.command == 'serve':
        app.run(host='127.0.0.1', port=args.port, debug=False)
    elif args.command == 'create-admin':
        email = args.email.strip().lower()
        if not re.fullmatch(r'[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+', email):
            parser.error('Enter a valid email')
        password = getpass.getpass('New admin password (12–128 characters): ')
        if not 12 <= len(password) <= 128:
            parser.error('Password length must be 12–128 characters')
        with app.app_context():
            if db().execute('SELECT id FROM users WHERE email=?', (email,)).fetchone():
                parser.error('Account already exists; no role or password was changed')
            db().execute("INSERT INTO users(email,password,role,verified) VALUES(?,?,'admin',1)", (email, generate_password_hash(password)))
            db().commit()
        print('Administrator created; locally provisioned address trusted by operator.')
    elif args.command == 'mail':
        while True:
            print(f'Processed {deliver(app, limit=5)} notifications ({app.config["MAIL_MODE"]}).', flush=True)
            if not args.watch:
                break
            time.sleep(10)
    elif args.command == 'doctor':
        from security_app.connections import status
        with app.app_context():
            print(json.dumps(status(app, db), indent=2))
    elif args.command == 'init-sensor':
        save_settings(app.config['INSTANCE'], {'SENSOR_TOKEN': app.config.get('SENSOR_TOKEN') or secrets.token_urlsafe(32)})
        print('Sensor key saved in private instance/settings.json. Restart the app. Do not place the key in React.')
    elif args.command == 'configure-location':
        import geoip2.database
        path = str(Path(args.database).resolve())
        with geoip2.database.Reader(path) as reader:
            if 'City' not in reader.metadata().database_type:
                parser.error('Use a City database')
        save_settings(app.config['INSTANCE'], {'GEOIP_DB': path})
        print('Approximate local lookup configured. Restart the app.')
    elif args.command == 'configure-email':
        host = input('SMTP host: ').strip()
        sender = input('Verified sender email: ').strip()
        username = input('SMTP username: ').strip()
        password = getpass.getpass('SMTP app password (hidden; stored in private local settings): ')
        if not host or not re.fullmatch(r'[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+', sender):
            parser.error('Invalid SMTP host or sender')
        save_settings(app.config['INSTANCE'], {'SMTP_HOST': host, 'SMTP_PORT': 587, 'SMTP_FROM': sender,
                      'SMTP_USER': username, 'SMTP_PASSWORD': password, 'MAIL_MODE': 'smtp'})
        print('STARTTLS SMTP configured. Restart app and mail worker. Pending messages will be sent; inbox delivery still needs checking.')


if __name__ == '__main__':
    main()

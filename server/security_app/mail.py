"""Durable notification queue. Local outbox by default; explicit SMTP opt-in."""
import os
import smtplib
import ssl
import time
import secrets
from email.message import EmailMessage
from pathlib import Path

from security_app.app import db


def deliver(app, limit=50):
    if app.config['MAIL_MODE'] == 'disabled':
        return 0  # Keep records pending in the database; never write a temporary outbox.
    with app.app_context():
        # Claim briefly; never hold the database write lock during network I/O.
        db().execute('BEGIN IMMEDIATE')
        db().execute("UPDATE notifications SET state='pending',claim_token=NULL WHERE state='sending' AND lease_until<?", (time.time(),))
        rows = db().execute("SELECT * FROM notifications WHERE state='pending' AND next_try<=? ORDER BY id LIMIT ?", (time.time(), limit)).fetchall()
        token = secrets.token_hex(16)
        for row in rows:
            db().execute("UPDATE notifications SET state='sending',claim_token=?,lease_until=? WHERE id=?", (token, time.time() + max(600, limit * 60), row['id']))
        db().commit()
        for row in rows:
            message = EmailMessage()
            try:
                message['From'] = app.config.get('SMTP_FROM') or 'security-demo@localhost'
                message['To'] = row['recipient']
                message['Subject'] = row['subject']
                message['Message-ID'] = f'<security-demo-{row["id"]}@localhost>'
                message.set_content(row['body'])
                if app.config['MAIL_MODE'] == 'outbox':
                    folder = Path(app.config['INSTANCE']) / 'outbox'
                    folder.mkdir(exist_ok=True, mode=0o700)
                    target = folder / f'{row["id"]}.eml'
                    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                    with os.fdopen(fd, 'w') as stream:
                        stream.write(message.as_string())
                    state = 'local-outbox'
                elif app.config['MAIL_MODE'] == 'smtp':
                    if not app.config.get('SMTP_FROM'):
                        raise ValueError('Configure a verified sender')
                    with smtplib.SMTP(app.config['SMTP_HOST'], int(app.config.get('SMTP_PORT', 587)), timeout=10) as smtp:
                        smtp.starttls(context=ssl.create_default_context())
                        if app.config.get('SMTP_USER'):
                            smtp.login(app.config['SMTP_USER'], app.config['SMTP_PASSWORD'])
                        smtp.send_message(message)
                    state = 'smtp-accepted'
                else:
                    raise ValueError('MAIL_MODE must be outbox or smtp')
                db().execute('UPDATE notifications SET state=?,attempts=attempts+1,error=NULL,claim_token=NULL WHERE id=? AND claim_token=?', (state, row['id'], token))
            except Exception as error:
                attempts = row['attempts'] + 1
                db().execute('UPDATE notifications SET state=?,attempts=?,error=?,next_try=?,claim_token=NULL WHERE id=? AND claim_token=?',
                             ('failed' if attempts >= 5 else 'pending', attempts, type(error).__name__, time.time() + min(3600, 60 * 2 ** attempts), row['id'], token))
            db().commit()
        return len(rows)

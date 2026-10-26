"""Trusted server-to-server account events, isolated from network sensor privileges."""
import hashlib
import hmac
import ipaddress
import json
import re
import time

from flask import abort, jsonify, request

DDL = '''
CREATE TABLE IF NOT EXISTS website_events(
 site_id TEXT, event_id TEXT, created REAL, occurred REAL, event_type TEXT,
 account_key TEXT, source_ip TEXT, success INTEGER, payload_hash TEXT,
 PRIMARY KEY(site_id,event_id));
CREATE TABLE IF NOT EXISTS website_accounts(
 site_id TEXT, account_key TEXT, email TEXT, verified INTEGER, updated REAL,
 PRIMARY KEY(site_id,account_key));
CREATE INDEX IF NOT EXISTS website_window ON website_events(site_id,occurred,account_key);
'''


def register_website(app, db, add_alert, queue_email):
    @app.post('/api/website-events')
    def website_event():
        token = app.config.get('WEBSITE_TOKEN', '')
        if not token or not hmac.compare_digest(request.headers.get('Authorization', ''), f'Bearer {token}'):
            abort(401)
        data = request.get_json(silent=True)
        try:
            if not isinstance(data, dict):
                raise ValueError('Expected a JSON object')
            kind = data.get('event_type')
            common = {'site_id', 'event_id', 'occurred_at', 'event_type', 'account_id'}
            fields = {'email', 'email_verified'} if kind == 'account.sync' else {'source_ip', 'success'}
            if kind not in ['account.sync', 'auth.result'] or set(data) != common | fields:
                raise ValueError('Invalid event fields; never send passwords, tokens or request bodies')
            site = data['site_id']
            if not isinstance(site, str) or not app.config.get('WEBSITE_ID') or site != app.config['WEBSITE_ID']:
                raise ValueError('Site is not provisioned')
            for key in ['event_id', 'account_id']:
                if not isinstance(data[key], str) or not re.fullmatch(r'[A-Za-z0-9_.:@-]{1,160}', data[key]):
                    raise ValueError(f'Invalid {key}')
            occurred = data['occurred_at']
            if isinstance(occurred, bool) or not isinstance(occurred, (float, int)) or not 0 < occurred < 1e12:
                raise ValueError('occurred_at must be Unix seconds')
            if kind == 'account.sync':
                email = data['email']
                if not isinstance(email, str) or len(email) > 254 or not re.fullmatch(r'[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+', email):
                    raise ValueError('Invalid registration email')
                if type(data['email_verified']) is not bool:
                    raise ValueError('email_verified must be boolean')
            else:
                if type(data['success']) is not bool:
                    raise ValueError('success must be boolean')
                ip = str(ipaddress.ip_address(data['source_ip']))
        except (TypeError, ValueError) as error:
            return jsonify(error=str(error)), 400
        digest = hashlib.sha256(json.dumps(data, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        now = time.time()
        key = hmac.new(app.secret_key.encode(), f'{site}:{data["account_id"]}'.encode(), hashlib.sha256).hexdigest()
        db().execute('BEGIN IMMEDIATE')
        prior = db().execute('SELECT payload_hash FROM website_events WHERE site_id=? AND event_id=?', (site, data['event_id'])).fetchone()
        if prior:
            db().rollback()
            if prior['payload_hash'] != digest:
                return jsonify(error='event_id already used for another event'), 409
            return jsonify(status='duplicate')
        if not now - 300 <= occurred <= now + 30:
            db().rollback()
            return jsonify(error='Event too old or clock skew too large; synchronize the source clock'), 400
        db().execute('INSERT INTO website_events VALUES(?,?,?,?,?,?,?,?,?)',
                     (site, data['event_id'], now, occurred, kind, key,
                      ip if kind == 'auth.result' else None, int(data['success']) if kind == 'auth.result' else None, digest))
        alert_id = None
        if kind == 'account.sync':
            # A delayed sync must not overwrite a newer verified-address change.
            db().execute('''INSERT INTO website_accounts VALUES(?,?,?,?,?)
                            ON CONFLICT(site_id,account_key) DO UPDATE SET email=excluded.email,
                            verified=excluded.verified,updated=excluded.updated
                            WHERE excluded.updated >= website_accounts.updated''',
                         (site, key, email.strip().lower(), int(data['email_verified']), occurred))
        else:
            failures = db().execute("SELECT COUNT(*) FROM website_events WHERE site_id=? AND account_key=? AND event_type='auth.result' AND success=0 AND occurred BETWEEN ? AND ?",
                                    (site, key, now - 300, now + 30)).fetchone()[0]
            evidence = {'method': 'Trusted website login result + expert rule; not the network ML model',
                        'site': site, 'rule': 'EXTERNAL_ACCOUNT_FAILURES_5M', 'threshold': 10,
                        'failed_attempts': failures, 'window_seconds': 300, 'current_login_succeeded': data['success'],
                        'interpretation': 'Possible password guessing; incorrect passwords by the owner can also match.'}
            if failures >= 10:
                alert_id = add_alert('website', None, ip, f'{site}: repeated failed sign-ins' if not data['success'] else f'{site}: success after repeated failures',
                                     evidence, 'Review the website authentication audit and contact the account owner. No blocking occurred.',
                                     f'website:{site}:{key}:{int(data["success"])}')
                account = db().execute('SELECT * FROM website_accounts WHERE site_id=? AND account_key=?', (site, key)).fetchone()
                if alert_id and account and account['verified']:
                    queue_email(account['email'], f'Security activity on {site}',
                                f'Unusual sign-in activity was observed for your account on {site}.\n'
                                f'Observed source IP: {ip}\nLocation context: {json.dumps(evidence["location"])}\n'
                                'This is not proof that your account was accessed. If this was not you, contact the website through your usual trusted channel. No automatic blocking occurred.')
            targets = db().execute("SELECT COUNT(DISTINCT account_key) FROM website_events WHERE site_id=? AND source_ip=? AND event_type='auth.result' AND success=0 AND occurred BETWEEN ? AND ?",
                                   (site, ip, now - 300, now + 30)).fetchone()[0]
            if targets >= 5:
                add_alert('website', None, ip, f'{site}: multiple accounts targeted',
                          {'method': 'Expert rule', 'site': site, 'rule': 'EXTERNAL_MULTI_ACCOUNT_5M', 'accounts': targets, 'threshold': 5,
                           'interpretation': 'Possible password spraying; shared network addresses can also match.'},
                          'Review website login logs. Do not identify a person from an IP alone.', f'website-spray:{site}:{ip}')
        db().commit()
        return jsonify(status='accepted', alert_id=alert_id), 201


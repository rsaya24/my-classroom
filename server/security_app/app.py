"""Local Flask demo: account monitoring, flow ingestion and evidence-linked alerts."""
import functools
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import time
from pathlib import Path

from flask import Flask, abort, flash, g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from security_app.detection import FlowModel, flow_rules, location, validate_flow
from security_app.settings import load_settings
from security_app.website import DDL as WEBSITE_DDL, register_website

DDL = '''
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL,
 password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', verified INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS verification(token TEXT PRIMARY KEY, user_id INTEGER, expires REAL);
CREATE TABLE IF NOT EXISTS auth_events(id INTEGER PRIMARY KEY, created REAL, user_id INTEGER,
 account_key TEXT, source_ip TEXT, success INTEGER);
CREATE TABLE IF NOT EXISTS flows(event_id TEXT PRIMARY KEY, created REAL, source_ip TEXT,
 collector TEXT, payload TEXT, prediction TEXT);
CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, created REAL, kind TEXT, user_id INTEGER,
 source_ip TEXT, title TEXT, evidence TEXT, recommendation TEXT, dedup_key TEXT, status TEXT DEFAULT 'open');
CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY, created REAL, recipient TEXT,
 subject TEXT, body TEXT, state TEXT DEFAULT 'pending', attempts INTEGER DEFAULT 0, error TEXT, next_try REAL DEFAULT 0);
CREATE INDEX IF NOT EXISTS auth_window ON auth_events(created, source_ip);
CREATE INDEX IF NOT EXISTS alert_dedup ON alerts(dedup_key, created);
'''


def db():
    if 'db' not in g:
        from flask import current_app
        g.db = sqlite3.connect(current_app.config['DATABASE'], timeout=15)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA journal_mode=WAL')
    return g.db


def queue_email(recipient, subject, body):
    db().execute('INSERT INTO notifications(created,recipient,subject,body) VALUES(?,?,?,?)',
                 (time.time(), recipient, subject, body))


def require_login(admin=False):
    def decorate(fn):
        @functools.wraps(fn)
        def wrapped(*args, **kwargs):
            if not g.user:
                return redirect(url_for('login'))
            if admin and g.user['role'] != 'admin':
                abort(403)
            return fn(*args, **kwargs)
        return wrapped
    return decorate


def create_app(config=None):
    project = Path(__file__).resolve().parents[1]
    instance = Path(os.environ.get('SECURITY_INSTANCE', project / 'instance')).resolve()
    if config and 'INSTANCE' in config:
        instance = Path(config['INSTANCE']).resolve()
    instance.mkdir(parents=True, exist_ok=True, mode=0o700)
    secret_file = instance / 'session.key'
    if not secret_file.exists():
        try:
            fd = os.open(secret_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'w') as stream:
                stream.write(secrets.token_hex(32))
        except FileExistsError:
            pass
    app = Flask(__name__)
    app.config.update(SECRET_KEY=secret_file.read_text().strip(), INSTANCE=str(instance),
                      DATABASE=str(instance / 'security.sqlite3'), MODEL_DIR=str(instance / 'model'),
                      SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax',
                      SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE') == '1',
                      MAX_CONTENT_LENGTH=32768, PUBLIC_URL=os.environ.get('PUBLIC_URL', 'http://127.0.0.1:5000'),
                      SENSOR_TOKEN=os.environ.get('SENSOR_TOKEN', ''), GEOIP_DB=os.environ.get('GEOIP_DB'),
                      ADMIN_EMAIL=os.environ.get('ADMIN_EMAIL', ''), MAIL_MODE=os.environ.get('MAIL_MODE', 'outbox'))
    app.config.update(load_settings(instance))
    if config:
        app.config.update(config)
    proxy_hops = int(app.config.get('TRUSTED_PROXY_HOPS', os.environ.get('TRUSTED_PROXY_HOPS', '0')))
    if proxy_hops not in (0, 1):
        raise ValueError('TRUSTED_PROXY_HOPS must be 0 or 1')
    if proxy_hops:
        # Enable only when ingress is restricted to one proxy that overwrites these headers.
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=0, x_port=0, x_prefix=0)
    with app.app_context():
        db().executescript(DDL)
        db().executescript(WEBSITE_DDL)
        columns = {row['name'] for row in db().execute('PRAGMA table_info(notifications)')}
        for column, kind in [('claim_token', 'TEXT'), ('lease_until', 'REAL DEFAULT 0')]:
            if column not in columns:
                db().execute(f'ALTER TABLE notifications ADD COLUMN {column} {kind}')
        db().commit()
        g.pop('db').close()
    Path(app.config['DATABASE']).chmod(0o600)
    try:
        app.extensions['flow_model'] = FlowModel(app.config['MODEL_DIR'])
    except FileNotFoundError:
        app.extensions['flow_model'] = None
    dummy_hash = generate_password_hash(secrets.token_hex(16))

    @app.teardown_appcontext
    def close_db(error):
        connection = g.pop('db', None)
        if connection:
            connection.close()

    @app.before_request
    def security():
        g.user = db().execute('SELECT * FROM users WHERE id=?', (session.get('user_id'),)).fetchone()
        if 'csrf' not in session:
            session['csrf'] = secrets.token_urlsafe(32)
        if request.method == 'POST' and request.endpoint not in {'ingest', 'website_event'}:
            supplied = request.headers.get('X-CSRF-Token') or request.form.get('csrf', '')
            if not hmac.compare_digest(session['csrf'], supplied):
                abort(400, 'Invalid CSRF token')

    @app.after_request
    def headers(response):
        response.headers.setdefault('Content-Security-Policy', "default-src 'self'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'")
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Cache-Control'] = 'no-store'
        return response

    @app.template_filter('when')
    def when(value):
        return time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(value))

    def add_alert(kind, user_id, ip, title, evidence, recommendation, key):
        now = time.time()
        if db().execute('SELECT id FROM alerts WHERE dedup_key=? AND created>?', (key, now - 900)).fetchone():
            return None
        evidence['location'] = location(ip, app.config['GEOIP_DB'])
        cursor = db().execute('INSERT INTO alerts(created,kind,user_id,source_ip,title,evidence,recommendation,dedup_key) VALUES(?,?,?,?,?,?,?,?)',
                              (now, kind, user_id, ip, title, json.dumps(evidence), recommendation, key))
        alert_id = cursor.lastrowid
        admins = db().execute("SELECT email FROM users WHERE role='admin' AND verified=1").fetchall()
        recipients = {r['email'] for r in admins}
        if app.config['ADMIN_EMAIL']:
            recipients.add(app.config['ADMIN_EMAIL'])
        for recipient in recipients:
            queue_email(recipient, f'[Security review #{alert_id}] {title}',
                        f'Observed source IP: {ip}\nEvidence:\n{json.dumps(evidence, indent=2)}\nRecommended review: {recommendation}\nNo automatic blocking occurred.')
        user = db().execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone() if user_id else None
        if user and user['verified']:
            queue_email(user['email'], 'Security activity affecting your account',
                        f'We noticed unusual sign-in activity involving your account.\nObserved source IP: {ip}\n'
                        f'Location information: {json.dumps(evidence["location"])}\n'
                        'This does not prove that your account was accessed. If this was not you, contact the website administrator through your usual trusted channel. No automatic blocking occurred.')
        return alert_id

    register_website(app, db, add_alert, queue_email)

    @app.get('/')
    def home():
        return render_template('home.html', model=app.extensions['flow_model'])

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if request.method == 'POST':
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '')
            if not re.fullmatch(r'[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+', email) or len(email) > 254 or not 12 <= len(password) <= 128:
                flash('Enter a valid email and a password between 12 and 128 characters.')
                return render_template('auth.html', mode='register'), 400
            try:
                cursor = db().execute('INSERT INTO users(email,password) VALUES(?,?)', (email, generate_password_hash(password)))
                token = secrets.token_urlsafe(32)
                db().execute('INSERT INTO verification VALUES(?,?,?)', (hashlib.sha256(token.encode()).hexdigest(), cursor.lastrowid, time.time() + 3600))
                queue_email(email, 'Verify your security-demo email',
                            f'Confirm your email within one hour:\n{app.config["PUBLIC_URL"]}/verify/{token}\nIgnore this message if you did not register.')
                db().commit()
            except sqlite3.IntegrityError:
                db().rollback()
            flash('If this is a new registration, a verification message has been queued. In local demo mode, ask the administrator to view the outbox.')
            return redirect(url_for('login'))
        return render_template('auth.html', mode='register')

    @app.route('/verify/<token>', methods=['GET', 'POST'])
    def verify(token):
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        record = db().execute('SELECT * FROM verification WHERE token=? AND expires>?', (token_hash, time.time())).fetchone()
        if not record:
            abort(400, 'Verification link expired or already used')
        if request.method == 'POST':
            db().execute('UPDATE users SET verified=1 WHERE id=?', (record['user_id'],))
            db().execute('DELETE FROM verification WHERE token=?', (token_hash,))
            db().commit()
            flash('Email verified. You can now receive account security notifications.')
            return redirect(url_for('login'))
        return render_template('verify.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            email = request.form.get('email', '').strip().lower()[:254]
            password = request.form.get('password', '')[:129]
            user = db().execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
            valid = check_password_hash(user['password'] if user else dummy_hash, password)
            ip = request.remote_addr or '127.0.0.1'  # Never trust a user-supplied X-Forwarded-For header.
            key = hmac.new(app.secret_key.encode(), email.encode(), hashlib.sha256).hexdigest()
            now = time.time()
            db().execute('BEGIN IMMEDIATE')
            db().execute('INSERT INTO auth_events(created,user_id,account_key,source_ip,success) VALUES(?,?,?,?,?)',
                         (now, user['id'] if user else None, key, ip, int(valid)))
            failures = db().execute('SELECT COUNT(*) FROM auth_events WHERE account_key=? AND success=0 AND created>?', (key, now - 300)).fetchone()[0]
            sources = db().execute('SELECT COUNT(DISTINCT account_key) FROM auth_events WHERE source_ip=? AND success=0 AND created>?', (ip, now - 300)).fetchone()[0]
            if failures >= 10:
                add_alert('authentication', user['id'] if user else None, ip,
                          'Successful sign-in after repeated failures' if valid else 'Repeated failed sign-ins',
                          {'method': 'Expert rule, not the CIC flow model', 'rule': 'ACCOUNT_FAILURES_5M',
                           'failed_attempts': failures, 'window_seconds': 300, 'threshold': 10, 'current_login_succeeded': valid,
                           'interpretation': 'Possible password guessing, but user mistakes can also match.'},
                          'Review sign-in logs and confirm activity with the account owner. Consider MFA and a password reset if unauthorized.',
                          f'account:{key}:{int(valid)}')
            if sources >= 5:
                add_alert('authentication', None, ip, 'Multiple accounts targeted from one source',
                          {'method': 'Expert rule', 'rule': 'MULTI_ACCOUNT_FAILURES_5M', 'accounts': sources, 'threshold': 5,
                           'interpretation': 'Possible password spraying; shared networks may also match.'},
                          'Review the source and affected-account logs. Do not equate an IP address with one person.', f'spray:{ip}')
            db().commit()
            if valid:
                session.clear()
                session['user_id'] = user['id']
                session['csrf'] = secrets.token_urlsafe(32)
                return redirect(url_for('dashboard') if user['role'] == 'admin' else url_for('account'))
            flash('Invalid email or password.')
            return render_template('auth.html', mode='login'), 401
        return render_template('auth.html', mode='login')

    @app.post('/logout')
    def logout():
        session.clear()
        return redirect(url_for('home'))

    @app.get('/account')
    @require_login()
    def account():
        alerts = db().execute('SELECT * FROM alerts WHERE user_id=? ORDER BY id DESC LIMIT 50', (g.user['id'],)).fetchall()
        return render_template('account.html', alerts=alerts)

    @app.get('/admin')
    @require_login(admin=True)
    def dashboard():
        alerts = db().execute('SELECT * FROM alerts ORDER BY id DESC LIMIT 100').fetchall()
        stats = {table: db().execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0] for table in ['flows', 'auth_events', 'alerts']}
        stats['pending'] = db().execute("SELECT COUNT(*) FROM notifications WHERE state='pending'").fetchone()[0]
        return render_template('dashboard.html', alerts=alerts, stats=stats, model=app.extensions['flow_model'])

    @app.get('/admin/alerts/<int:alert_id>')
    @require_login(admin=True)
    def alert_detail(alert_id):
        alert = db().execute('SELECT * FROM alerts WHERE id=?', (alert_id,)).fetchone()
        if not alert:
            abort(404)
        return render_template('alert.html', alert=alert, evidence=json.loads(alert['evidence']))

    @app.post('/admin/alerts/<int:alert_id>/explain')
    @require_login(admin=True)
    def explain_alert(alert_id):
        alert = db().execute('SELECT * FROM alerts WHERE id=?', (alert_id,)).fetchone()
        if not alert:
            abort(404)
        evidence = json.loads(alert['evidence'])
        if 'flow_features' not in evidence:
            return jsonify(error='Only newly ingested network alerts support SHAP/LIME'), 400
        from security_app.explain import explain
        try:
            evidence['xai'] = explain(app.extensions['flow_model'], evidence['flow_features'])
        except (ImportError, OSError, ValueError) as error:
            app.logger.warning('Explanation unavailable: %s', error)
            return jsonify(error='Explanation dependencies or matching background are unavailable'), 503
        db().execute('UPDATE alerts SET evidence=? WHERE id=?', (json.dumps(evidence), alert_id))
        db().commit()
        return redirect(url_for('alert_detail', alert_id=alert_id))

    @app.post('/admin/alerts/<int:alert_id>/review')
    @require_login(admin=True)
    def review(alert_id):
        db().execute("UPDATE alerts SET status='reviewed' WHERE id=?", (alert_id,))
        db().commit()
        return redirect(url_for('alert_detail', alert_id=alert_id))

    @app.get('/admin/outbox')
    @require_login(admin=True)
    def outbox():
        messages = db().execute('SELECT * FROM notifications ORDER BY id DESC LIMIT 100').fetchall()
        return render_template('outbox.html', messages=messages, mode=app.config['MAIL_MODE'])

    @app.get('/admin/connections')
    @require_login(admin=True)
    def connections():
        from security_app.connections import status
        return render_template('connections.html', rows=status(app, db))

    @app.post('/api/flows')
    def ingest():
        token = app.config['SENSOR_TOKEN']
        if not token or not hmac.compare_digest(request.headers.get('Authorization', ''), f'Bearer {token}'):
            abort(401)
        data = request.get_json(silent=True)
        try:
            row = validate_flow(data)
            event_id = data.get('event_id', '')
            if not isinstance(event_id, str) or not re.fullmatch(r'[\w.:-]{1,160}', event_id):
                raise ValueError('A valid unique event_id is required')
            ip = str(ipaddress.ip_address(data.get('source_ip', '')))
            collector = data.get('collector')
            if collector not in ['cic-csv-replay', 'zeek-experimental']:
                raise ValueError('Unsupported collector')
            if any(k in data for k in ['user_id', 'email', 'account']):
                raise ValueError('Network flows cannot assert an account identity')
        except (ValueError, TypeError) as error:
            return jsonify(error=str(error)), 400
        model = app.extensions['flow_model']
        if model is None:
            return jsonify(error='Train the CIC model before ingesting flows'), 503
        prediction = model.predict(row)
        hits = flow_rules(row)
        db().execute('BEGIN IMMEDIATE')
        existing = db().execute('SELECT payload FROM flows WHERE event_id=?', (event_id,)).fetchone()
        if existing:
            db().rollback()
            if json.loads(existing['payload']) != data:
                return jsonify(error='event_id already used for a different payload'), 409
            return jsonify(status='duplicate', event_id=event_id)
        db().execute('INSERT INTO flows VALUES(?,?,?,?,?,?)', (event_id, time.time(), ip, collector, json.dumps(data), json.dumps(prediction)))
        alert_id = None
        if prediction['attack_prediction'] or hits:
            alert_id = add_alert('network', None, ip, 'Network flow requires review',
                                 {'ml': prediction, 'rules': hits, 'collector': collector,
                                  'flow_features': dict(zip(['duration_seconds', 'forward_packets', 'backward_packets', 'destination_port'], row.tolist())),
                                  'model_rule_agreement': prediction['attack_prediction'] == bool(hits),
                                  'account_mapping': 'None: flow data does not identify a registered account',
                                  'domain_warning': 'Replayed benchmark, not live traffic' if collector == 'cic-csv-replay' else 'Experimental cross-collector scoring: Zeek session boundaries differ from CIC'},
                                 'Inspect the flow and surrounding service logs. Corroborate the evidence before taking action.',
                                 f'flow:{collector}:{ip}')
        db().commit()
        return jsonify(status='accepted', event_id=event_id, prediction=prediction, rules=hits, alert_id=alert_id), 201

    @app.get('/health')
    def health():
        return jsonify(status='ok', model_loaded=app.extensions['flow_model'] is not None)

    return app

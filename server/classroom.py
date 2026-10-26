"""Classroom API and UI served alongside the integrated security engine."""
import json
from pathlib import Path

from flask import g, jsonify, redirect, request, send_from_directory, session

from security_app.app import create_app as security_app, db

SUBJECTS = {'cloud': 12, 'operating': 10, 'networks': 10}
TASKS = ['cloud-models', 'process-scheduling', 'tcp-ip', 'virtualization']


def create_app(config=None):
    root = Path(__file__).resolve().parent
    settings = {'MODEL_DIR': str(root / 'models' / 'cic-tree'), 'PUBLIC_URL': 'http://127.0.0.1:5001',
                'SESSION_COOKIE_NAME': 'classroom_session'}
    if config:
        settings.update(config)
    # Environment config remains effective unless explicitly overridden by a test.
    import os
    for key in ['PUBLIC_URL', 'MODEL_DIR']:
        if key in os.environ and (not config or key not in config):
            settings[key] = os.environ[key]
    app = security_app(settings)
    with app.app_context():
        db().execute('CREATE TABLE IF NOT EXISTS classroom_progress(user_id INTEGER PRIMARY KEY, payload TEXT NOT NULL)')
        db().commit()
    app.view_functions['home'] = lambda: redirect('/classroom')

    @app.after_request
    def classroom_headers(response):
        # Only dynamic progress-bar style attributes require inline styles; no inline scripts.
        if request.path.startswith('/classroom'):
            response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self'; style-src-attr 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'"
        if request.endpoint == 'login' and request.method == 'POST' and response.status_code == 302:
            response.headers['Location'] = '/classroom'
        return response

    @app.get('/classroom')
    def classroom_page():
        dist = root.parent / 'client' / 'dist'
        if not (dist / 'index.html').exists():
            return 'Build the classroom client first: cd client && npm ci && npm run build', 503
        return send_from_directory(dist, 'index.html')

    @app.get('/assets/<path:filename>')
    def classroom_assets(filename):
        return send_from_directory(root.parent / 'client' / 'dist' / 'assets', filename)

    @app.get('/favicon.svg')
    def favicon():
        return send_from_directory(root.parent / 'client' / 'public', 'favicon.svg')

    @app.get('/api/session')
    def current_session():
        user = {k: g.user[k] for k in ['id', 'email', 'role', 'verified']} if g.user else None
        return jsonify(user=user, csrf=session['csrf'])

    @app.route('/api/classroom/progress', methods=['GET', 'POST'])
    def progress():
        if not g.user:
            return jsonify(error='Sign in required'), 401
        if request.method == 'POST':
            data = request.get_json(silent=True)
            if not isinstance(data, dict) or set(data) != {'completed', 'tasks'}:
                return jsonify(error='Invalid progress structure'), 400
            counts, tasks = data['completed'], data['tasks']
            if not isinstance(counts, dict) or set(counts) != set(SUBJECTS) or any(type(counts[k]) is not int or not 0 <= counts[k] <= SUBJECTS[k] for k in SUBJECTS):
                return jsonify(error='Invalid subject progress'), 400
            if not isinstance(tasks, dict) or set(tasks) != set(TASKS) or any(type(v) is not bool for v in tasks.values()):
                return jsonify(error='Invalid task progress'), 400
            db().execute('INSERT INTO classroom_progress VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET payload=excluded.payload', (g.user['id'], json.dumps(data)))
            db().commit()
        record = db().execute('SELECT payload FROM classroom_progress WHERE user_id=?', (g.user['id'],)).fetchone()
        payload = json.loads(record['payload']) if record else {'completed': {k: 0 for k in SUBJECTS}, 'tasks': {k: False for k in TASKS}}
        return jsonify(payload)

    @app.get('/api/classroom/security')
    def account_security():
        if not g.user:
            return jsonify(error='Sign in required'), 401
        rows = db().execute('SELECT id,title,created,source_ip,status,evidence FROM alerts WHERE user_id=? ORDER BY id DESC LIMIT 20', (g.user['id'],)).fetchall()
        # Do not disclose other accounts, administrator recipients or verification tokens.
        return jsonify(alerts=[{'id': r['id'], 'title': r['title'], 'created': r['created'],
                               'source_ip': r['source_ip'], 'status': r['status'],
                               'explanation': json.loads(r['evidence'])} for r in rows],
                       email_mode=app.config['MAIL_MODE'])

    return app

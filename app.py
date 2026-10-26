"""Vercel entry point. Never fall back to temporary SQLite or a random session key."""
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent / 'server'))


def create_vercel_app():
    from flask import Flask, jsonify
    url = os.environ.get('DATABASE_URL', '')
    public = urlsplit(os.environ.get('PUBLIC_URL', ''))
    problems = []
    if not url.startswith(('postgresql://', 'postgres://')):
        problems.append('DATABASE_URL')
    if len(os.environ.get('SESSION_SECRET', '')) < 32:
        problems.append('SESSION_SECRET')
    if public.scheme != 'https' or not public.hostname or public.username or public.path not in ('', '/') or public.query or public.fragment:
        problems.append('PUBLIC_URL')
    if problems:
        application = Flask(__name__)

        @application.route('/', defaults={'path': ''}, methods=['GET', 'POST'])
        @application.route('/<path:path>', methods=['GET', 'POST'])
        def unavailable(path):
            response = jsonify(error='Backend setup is incomplete. Ask the project administrator to configure the deployment.',
                               missing_configuration=problems)
            response.status_code = 503
            response.headers['Cache-Control'] = 'no-store'
            return response
        return application

    from classroom import create_app
    return create_app({
        'INSTANCE': '/tmp/classroom-runtime',
        'INIT_DATABASE': False,
        'SESSION_COOKIE_SECURE': True,
        # Vercel overwrites X-Forwarded-For. Never enable this on direct local ingress.
        'TRUSTED_PROXY_HOPS': 1 if os.environ.get('VERCEL') == '1' else 0,
        'MAIL_MODE': os.environ.get('MAIL_MODE', 'disabled'),
        'MAIL_DELIVERY': os.environ.get('MAIL_DELIVERY', 'manual'),
    })


app = create_vercel_app()

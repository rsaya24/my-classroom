import importlib.util
from pathlib import Path

from classroom import create_app
from security_app.app import db, queue_email
from security_app.database import Row, postgres_sql
from security_app.mail import deliver


def entrypoint():
    spec = importlib.util.spec_from_file_location('vercel_entry', Path(__file__).resolve().parents[2] / 'app.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_missing_vercel_secrets_fail_closed(monkeypatch):
    for key in ['DATABASE_URL', 'SESSION_SECRET', 'PUBLIC_URL']:
        monkeypatch.delenv(key, raising=False)
    application = entrypoint().app
    result = application.test_client().get('/api/session')
    assert result.status_code == 503
    assert set(result.json['missing_configuration']) == {'DATABASE_URL', 'SESSION_SECRET', 'PUBLIC_URL'}
    assert 'no-store' in result.headers['Cache-Control']


def test_vercel_factory_has_no_database_connection_at_import(monkeypatch):
    monkeypatch.setenv('DATABASE_URL', 'postgresql://unused.invalid/classroom?sslmode=require')
    monkeypatch.setenv('SESSION_SECRET', 'test-only-session-secret-not-a-real-credential')
    monkeypatch.setenv('PUBLIC_URL', 'https://preview.example.test')
    monkeypatch.setenv('VERCEL', '1')
    application = entrypoint().app
    assert application.config['INIT_DATABASE'] is False
    assert application.config['SESSION_COOKIE_SECURE']
    assert application.config['MAIL_MODE'] == 'disabled'
    assert application.extensions['flow_model'] is not None


def test_postgres_schema_keeps_timestamp_precision_and_non_generated_ids():
    sql = postgres_sql('CREATE TABLE events(id INTEGER PRIMARY KEY, user_id INTEGER, created REAL)')
    assert 'id BIGSERIAL PRIMARY KEY' in sql
    assert 'user_id INTEGER' in sql
    assert 'created DOUBLE PRECISION' in sql
    assert 'user_id INTEGER PRIMARY KEY' in postgres_sql('user_id INTEGER PRIMARY KEY')
    assert postgres_sql('SELECT * FROM users WHERE email=?') == 'SELECT * FROM users WHERE email=%s'
    row = Row(id=5, email='sample@example.test')
    assert row[0] == row['id'] == 5


def test_disabled_mail_preserves_pending_queue(tmp_path):
    application = create_app({'TESTING': True, 'INSTANCE': str(tmp_path), 'MAIL_MODE': 'disabled'})
    with application.app_context():
        queue_email('sample@example.test', 'test', 'test')
        db().commit()
    assert deliver(application) == 0
    with application.app_context():
        assert db().execute('SELECT state FROM notifications').fetchone()[0] == 'pending'
    assert not (tmp_path / 'outbox').exists()


def test_mail_job_requires_secret_and_smtp(tmp_path, monkeypatch):
    application = create_app({'TESTING': True, 'INSTANCE': str(tmp_path), 'MAIL_MODE': 'disabled'})
    client = application.test_client()
    monkeypatch.delenv('CRON_SECRET', raising=False)
    assert client.get('/api/jobs/mail').status_code == 401
    monkeypatch.setenv('CRON_SECRET', 'test-only-cron-secret-at-least-32-characters')
    assert client.get('/api/jobs/mail', headers={'Authorization': 'Bearer wrong'}).status_code == 401
    result = client.get('/api/jobs/mail', headers={'Authorization': 'Bearer test-only-cron-secret-at-least-32-characters'})
    assert result.status_code == 503


def test_inline_delivery_is_opt_in(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr('security_app.mail.deliver', lambda application, limit: calls.append(limit))
    application = create_app({'TESTING': True, 'INSTANCE': str(tmp_path), 'MAIL_MODE': 'smtp', 'MAIL_DELIVERY': 'inline'})
    client = application.test_client()
    csrf = client.get('/api/session').json['csrf']
    response = client.post('/register', data={'csrf': csrf, 'email': 'test@example.test', 'password': 'test-password-long-enough'})
    assert response.status_code == 302
    assert calls == [2]

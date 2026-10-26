"""Opt-in integration tests: use ONLY an empty, disposable PostgreSQL database."""
import os
import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from classroom import create_app, SUBJECTS, TASKS
from security_app.app import db, queue_email
from security_app.mail import deliver

pytestmark = pytest.mark.skipif(not os.environ.get('CLASSROOM_TEST_DATABASE_URL'), reason='Disposable PostgreSQL database not configured')


@pytest.fixture
def pg_app(tmp_path):
    url = os.environ['CLASSROOM_TEST_DATABASE_URL']
    application = create_app({'TESTING': True, 'INSTANCE': str(tmp_path), 'DATABASE_URL': url,
                              'MAIL_MODE': 'outbox', 'SENSOR_TOKEN': 'test-sensor', 'INIT_DATABASE': True})
    with application.app_context():
        assert db().execute('SELECT COUNT(*) FROM users').fetchone()[0] == 0, 'Use an empty disposable test database'
    return application


def test_postgres_end_to_end(pg_app):
    client = pg_app.test_client()
    csrf = client.get('/api/session').json['csrf']
    data = {'csrf': csrf, 'email': 'postgres@example.test', 'password': 'test-password-long-enough'}
    assert client.post('/register', data=data).status_code == 302
    assert client.post('/register', data=data).status_code == 302  # Unique violation is rolled back.
    with pg_app.app_context():
        user = db().execute('SELECT * FROM users WHERE email=?', ('postgres@example.test',)).fetchone()
        assert user['id'] > 0
        db().execute('UPDATE users SET verified=1 WHERE id=?', (user['id'],))
        db().commit()
        # REAL must map to double precision or Unix timestamps lose the 5-minute window.
        import time
        timestamp = time.time()
        db().execute('INSERT INTO auth_events(created,success) VALUES(?,?)', (timestamp, 1))
        db().commit()
        assert db().execute('SELECT created FROM auth_events').fetchone()[0] == timestamp
    for _ in range(10):
        assert client.post('/login', data={'csrf': csrf, 'email': data['email'], 'password': 'wrong'}).status_code == 401
    with pg_app.app_context():
        assert db().execute('SELECT COUNT(*) FROM alerts').fetchone()[0] == 1
    assert client.post('/login', data=data).status_code == 302
    csrf = client.get('/api/session').json['csrf']
    progress = {'completed': {k: 0 for k in SUBJECTS}, 'tasks': {k: False for k in TASKS}}
    assert client.post('/api/classroom/progress', json=progress, headers={'X-CSRF-Token': csrf}).status_code == 200
    assert client.get('/api/classroom/progress').json == progress
    assert client.get('/admin').status_code == 403
    payload = dict(event_id='pg-flow-1', source_ip='192.0.2.44', collector='cic-csv-replay',
                   duration_seconds=1, forward_packets=2000, backward_packets=0, destination_port=443)
    headers = {'Authorization': 'Bearer test-sensor'}
    assert client.post('/api/flows', json=payload).status_code == 401
    def ingest(_):
        with pg_app.test_client() as sensor:
            return sensor.post('/api/flows', json=payload, headers=headers).json['status']
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(ingest, range(2))) == ['accepted', 'duplicate']
    assert client.post('/api/flows', json={**payload, 'forward_packets': 3000}, headers=headers).status_code == 409
    # Two workers must not claim the same pending records.
    with ThreadPoolExecutor(max_workers=2) as pool:
        counts = list(pool.map(lambda _: deliver(pg_app, limit=50), range(2)))
    assert sum(counts) >= 1
    with pg_app.app_context():
        assert db().execute('SELECT MAX(attempts) FROM notifications').fetchone()[0] == 1
        assert db().execute("SELECT COUNT(*) FROM notifications WHERE state='pending'").fetchone()[0] == 0
        queue_email('rollback@example.test', 'test', 'test')
        db().rollback()
        assert not db().execute('SELECT * FROM notifications WHERE recipient=?', ('rollback@example.test',)).fetchone()
    # A second process/app reads durable state and does not recreate a local SQLite file.
    other = create_app({'TESTING': True, 'INSTANCE': pg_app.config['INSTANCE'],
                        'DATABASE_URL': pg_app.config['DATABASE_URL'], 'INIT_DATABASE': False})
    with other.app_context():
        assert db().execute('SELECT COUNT(*) FROM users').fetchone()[0] == 1
        assert json.loads(db().execute('SELECT payload FROM classroom_progress').fetchone()[0]) == progress

import json
import time

import numpy as np
import pytest
from werkzeug.security import generate_password_hash

from classroom import create_app, SUBJECTS, TASKS
from security_app.app import db, queue_email
from security_app.mail import deliver
from security_app.sensor import zeek_flow


@pytest.fixture
def app(tmp_path):
    application = create_app({'TESTING': True, 'INSTANCE': str(tmp_path), 'SENSOR_TOKEN': 'sensor-test',
                              'MAIL_MODE': 'outbox', 'WEBSITE_ID': 'classroom.test', 'WEBSITE_TOKEN': 'website-test'})
    with application.app_context():
        for email, role in [('student@example.test', 'user'), ('other@example.test', 'user'), ('admin@example.test', 'admin')]:
            db().execute('INSERT INTO users(email,password,role,verified) VALUES(?,?,?,1)', (email, generate_password_hash('classroom-test-password'), role))
        db().commit()
    return application


def login(client, email='student@example.test', password='classroom-test-password'):
    csrf = client.get('/api/session').json['csrf']
    return client.post('/login', data={'csrf': csrf, 'email': email, 'password': password})


def test_session_and_progress_isolation(app):
    first, second = app.test_client(), app.test_client()
    assert first.get('/api/session').json['user'] is None
    assert first.get('/api/classroom/progress').status_code == 401
    assert login(first).headers['Location'] == '/classroom'
    csrf = first.get('/api/session').json['csrf']
    payload = {'completed': dict.fromkeys(SUBJECTS, 1), 'tasks': dict.fromkeys(TASKS, True)}
    assert first.post('/api/classroom/progress', json=payload).status_code == 400
    assert first.post('/api/classroom/progress', json=payload, headers={'X-CSRF-Token': csrf}).status_code == 200
    login(second, 'other@example.test')
    assert second.get('/api/classroom/progress').json['completed']['cloud'] == 0
    assert first.get('/api/classroom/progress').json == payload
    assert first.get('/admin').status_code == 403
    assert first.get('/admin/connections').status_code == 403


def test_progress_rejects_extra_identity_and_bad_values(app):
    client = app.test_client()
    login(client)
    csrf = client.get('/api/session').json['csrf']
    payload = {'completed': dict.fromkeys(SUBJECTS, 0), 'tasks': dict.fromkeys(TASKS, False)}
    for invalid in [{**payload, 'user_id': 2}, {**payload, 'completed': dict.fromkeys(SUBJECTS, True)},
                    {**payload, 'completed': dict.fromkeys(SUBJECTS, 999)}, {**payload, 'tasks': {}}]:
        assert client.post('/api/classroom/progress', json=invalid, headers={'X-CSRF-Token': csrf}).status_code == 400


def test_resend_verification_is_scoped_throttled_and_invalidates_old_link(app):
    client = app.test_client()
    login(client)
    with app.app_context():
        uid = db().execute("SELECT id FROM users WHERE email='student@example.test'").fetchone()['id']
        db().execute('UPDATE users SET verified=0 WHERE id=?', (uid,))
        db().execute('INSERT INTO verification VALUES(?,?,?)', ('expired-hash', uid, time.time()-1))
        queue_email('student@example.test', 'Verify your security-demo email', 'old expired message')
        db().commit()
    assert client.post('/account/resend-verification').status_code == 400
    csrf = client.get('/api/session').json['csrf']
    for _ in range(2):
        assert client.post('/account/resend-verification', data={'csrf': csrf}).status_code == 302
    with app.app_context():
        assert db().execute('SELECT COUNT(*) FROM verification WHERE user_id=?', (uid,)).fetchone()[0] == 1
        assert db().execute("SELECT COUNT(*) FROM verification WHERE token='expired-hash'").fetchone()[0] == 0
        rows = db().execute('SELECT state FROM notifications ORDER BY id').fetchall()
        assert [r['state'] for r in rows] == ['superseded', 'pending']


def test_full_account_alert_to_local_notifications(app):
    client = app.test_client()
    for _ in range(10):
        assert login(client, password='deliberately-wrong').status_code == 401
    login(client)
    report = client.get('/api/classroom/security').json
    assert report['alerts']
    assert report['alerts'][0]['explanation']['failed_attempts'] == 10
    assert report['email_mode'] == 'outbox'
    assert deliver(app) >= 2
    with app.app_context():
        messages = db().execute('SELECT recipient,state FROM notifications').fetchall()
        assert {row['recipient'] for row in messages} == {'admin@example.test', 'student@example.test'}
        assert {row['state'] for row in messages} == {'local-outbox'}
    stranger = app.test_client()
    login(stranger, 'other@example.test')
    assert stranger.get('/api/classroom/security').json['alerts'] == []


def test_tree_explanations_and_sensor_route(app):
    client = app.test_client()
    flow = zeek_flow({'id.orig_h': '192.0.2.44', 'id.resp_p': 80, 'duration': .2, 'orig_pkts': 2000, 'resp_pkts': 0})
    response = client.post('/api/flows', json=flow, headers={'Authorization': 'Bearer sensor-test'})
    assert response.status_code == 201
    explanation = response.json['prediction']
    assert explanation['explanation_type'] == 'tree-path'
    assert np.isclose(explanation['baseline_score'] + sum(t['score_contribution'] for t in explanation['contributions']), explanation['score'])
    assert response.json['alert_id']
    login(client, 'admin@example.test')
    page = client.get('/admin/alerts/' + str(response.json['alert_id']))
    assert page.status_code == 200 and b'Decision taken' in page.data
    endpoint = '/admin/alerts/' + str(response.json['alert_id']) + '/explain'
    assert client.post(endpoint).status_code == 400
    csrf = client.get('/api/session').json['csrf']
    explained = client.post(endpoint, data={'csrf': csrf}, follow_redirects=True)
    assert explained.status_code == 200
    assert b'Local fidelity' in explained.data and b'Reconstructed score' in explained.data
    assert client.get('/admin/connections').status_code == 200


def test_mail_recovers_expired_claim_but_not_active_claim(app):
    with app.app_context():
        queue_email('expired@example.test', 'Expired', 'Test')
        queue_email('active@example.test', 'Active', 'Test')
        db().execute("UPDATE notifications SET state='sending',claim_token='old',lease_until=? WHERE recipient=?", (time.time() - 1, 'expired@example.test'))
        db().execute("UPDATE notifications SET state='sending',claim_token='active',lease_until=? WHERE recipient=?", (time.time() + 600, 'active@example.test'))
        db().commit()
    assert deliver(app) == 1
    with app.app_context():
        states = {r['recipient']: r['state'] for r in db().execute('SELECT recipient,state FROM notifications')}
        assert states['expired@example.test'] == 'local-outbox'
        assert states['active@example.test'] == 'sending'


def test_smtp_uses_saved_config_and_tls_without_real_delivery(app, monkeypatch):
    calls = []
    class FakeSMTP:
        def __init__(self, host, port, timeout):
            assert host == 'smtp.example.test' and port == 587
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def starttls(self, context): calls.append('tls')
        def login(self, username, password):
            assert username == 'sender' and password == 'test-only-secret'
            calls.append('login')
        def send_message(self, message): calls.append('send')
    monkeypatch.setattr('security_app.mail.smtplib.SMTP', FakeSMTP)
    app.config.update(MAIL_MODE='smtp', SMTP_HOST='smtp.example.test', SMTP_PORT=587,
                      SMTP_FROM='sender@example.test', SMTP_USER='sender', SMTP_PASSWORD='test-only-secret')
    with app.app_context():
        queue_email('student@example.test', 'Test', 'Synthetic message')
        db().commit()
    assert deliver(app) == 1 and calls == ['tls', 'login', 'send']
    with app.app_context():
        assert db().execute('SELECT state FROM notifications').fetchone()[0] == 'smtp-accepted'


def test_external_credentials_are_separate_and_events_idempotent(app):
    client = app.test_client()
    sync = {'site_id': 'classroom.test', 'event_id': 'sync-1', 'occurred_at': time.time(),
            'event_type': 'account.sync', 'account_id': '42', 'email': 'external@example.test', 'email_verified': True}
    assert client.post('/api/website-events', json=sync, headers={'Authorization': 'Bearer sensor-test'}).status_code == 401
    headers = {'Authorization': 'Bearer website-test'}
    assert client.post('/api/website-events', json=sync, headers=headers).status_code == 201
    assert client.post('/api/website-events', json=sync, headers=headers).json['status'] == 'duplicate'
    assert client.post('/api/website-events', json={**sync, 'email': 'other@example.test'}, headers=headers).status_code == 409
    for i in range(10):
        event = {'site_id': 'classroom.test', 'event_id': f'auth-{i}', 'occurred_at': time.time(),
                 'event_type': 'auth.result', 'account_id': '42', 'source_ip': '192.0.2.44', 'success': False}
        assert client.post('/api/website-events', json=event, headers=headers).status_code == 201
    with app.app_context():
        recipients = {r[0] for r in db().execute('SELECT recipient FROM notifications')}
        assert recipients == {'external@example.test', 'admin@example.test'}


def test_model_partition_audit():
    from pathlib import Path
    folder = Path(__file__).resolve().parents[1] / 'models' / 'cic-tree'
    meta = json.loads((folder / 'metadata.json').read_text())
    assert all(not name.startswith('Friday') for name in meta['training_sources'])
    assert meta['validation_rows'] > 0

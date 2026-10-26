import hashlib
import json
import re
import time

import numpy as np
import pytest
from werkzeug.security import generate_password_hash

from security_app.app import create_app, db
from security_app.detection import FIELDS, SCHEMA, FlowModel, location, validate_flow
from security_app.mail import deliver
from security_app.sensor import zeek_flow
from src.model import StandardLogisticRegression


@pytest.fixture
def app(tmp_path):
    model_dir = tmp_path / 'model'
    model_dir.mkdir()
    model = StandardLogisticRegression(epochs=20).fit(np.array([[0, 0, 0, 0], [1, 2, 3, 4], [10, 10, 10, 10.]]), np.array([0, 0, 1]))
    np.savez(model_dir / 'model.npz', **{n: getattr(model, n) for n in ['mean_', 'scale_', 'coef_', 'intercept_']})
    (model_dir / 'metadata.json').write_text(json.dumps({'schema': SCHEMA, 'features': FIELDS}))
    app = create_app({'TESTING': True, 'INSTANCE': str(tmp_path), 'SENSOR_TOKEN': 'test-token'})
    with app.app_context():
        for email, role, verified in [('admin@example.test', 'admin', 1), ('user@example.test', 'user', 1), ('unverified@example.test', 'user', 0)]:
            db().execute('INSERT INTO users(email,password,role,verified) VALUES(?,?,?,?)',
                         (email, generate_password_hash('long-demo-password'), role, verified))
        db().commit()
    return app


def post(client, path, **data):
    client.get('/login')
    with client.session_transaction() as session:
        data['csrf'] = session['csrf']
    return client.post(path, data=data)


def flow(**overrides):
    return dict(event_id='unit-test-1', source_ip='192.0.2.44', collector='cic-csv-replay', duration_seconds=1,
                forward_packets=2000, backward_packets=0, destination_port=443, **overrides)


def test_auth_alert_and_delivery(app):
    client = app.test_client()
    for _ in range(11):
        assert post(client, '/login', email='user@example.test', password='incorrect').status_code == 401
    with app.app_context():
        assert db().execute('SELECT COUNT(*) FROM alerts').fetchone()[0] == 1
        recipients = {r[0] for r in db().execute('SELECT recipient FROM notifications')}
        assert recipients == {'user@example.test', 'admin@example.test'}
        assert 'incorrect' not in db().execute('SELECT evidence FROM alerts').fetchone()[0]
    assert deliver(app) == 2
    with app.app_context():
        assert {r[0] for r in db().execute('SELECT state FROM notifications')} == {'local-outbox'}
    assert post(client, '/login', email='user@example.test', password='long-demo-password').status_code == 302
    assert client.get('/account').status_code == 200
    assert client.get('/admin').status_code == 403
    assert client.get('/admin/outbox').status_code == 403


def test_unverified_no_security_mail(app):
    client = app.test_client()
    for _ in range(10):
        post(client, '/login', email='unverified@example.test', password='wrong')
    with app.app_context():
        assert [r[0] for r in db().execute('SELECT recipient FROM notifications')] == ['admin@example.test']


def test_network_auth_validation_dedup_and_no_account_mapping(app):
    client = app.test_client()
    assert client.post('/api/flows', json=flow()).status_code == 401
    headers = {'Authorization': 'Bearer test-token'}
    assert client.post('/api/flows', json={**flow(), 'user_id': 2}, headers=headers).status_code == 400
    assert client.post('/api/flows', json={**flow(), 'forward_packets': -1}, headers=headers).status_code == 400
    response = client.post('/api/flows', json=flow(), headers=headers)
    assert response.status_code == 201
    assert response.json['rules']
    assert client.post('/api/flows', json=flow(), headers=headers).json['status'] == 'duplicate'
    assert client.post('/api/flows', json={**flow(), 'forward_packets': 3000}, headers=headers).status_code == 409
    with app.app_context():
        assert db().execute('SELECT COUNT(*) FROM flows').fetchone()[0] == 1
        assert db().execute('SELECT user_id FROM alerts').fetchone()[0] is None
        assert [r[0] for r in db().execute('SELECT recipient FROM notifications')] == ['admin@example.test']


def test_csrf_and_header_spoofing(app):
    client = app.test_client()
    assert client.post('/login', data={'email': 'user@example.test'}).status_code == 400
    client.get('/login')
    with client.session_transaction() as session:
        csrf = session['csrf']
    client.post('/login', data={'csrf': csrf, 'email': 'user@example.test', 'password': 'wrong'}, headers={'X-Forwarded-For': '8.8.8.8'})
    with app.app_context():
        assert db().execute('SELECT source_ip FROM auth_events').fetchone()[0] == '127.0.0.1'


def test_registration_verification_single_use(app):
    client = app.test_client()
    assert post(client, '/register', email='new@example.test', password='new-long-password').status_code == 302
    with app.app_context():
        body = db().execute("SELECT body FROM notifications WHERE recipient='new@example.test'").fetchone()[0]
    path = '/verify/' + re.search(r'/verify/([^\s]+)', body).group(1)
    assert client.get(path).status_code == 200
    assert post(client, path).status_code == 302
    assert client.get(path).status_code == 400
    with app.app_context():
        assert db().execute("SELECT verified FROM users WHERE email='new@example.test'").fetchone()[0] == 1


def test_expired_verification(app):
    with app.app_context():
        db().execute('INSERT INTO verification VALUES(?,?,?)', (hashlib.sha256(b'expired').hexdigest(), 2, time.time() - 1))
        db().commit()
    assert app.test_client().get('/verify/expired').status_code == 400


def test_admin_pages_and_review(app):
    client = app.test_client()
    client.post('/api/flows', json=flow(), headers={'Authorization': 'Bearer test-token'})
    post(client, '/login', email='admin@example.test', password='long-demo-password')
    for path in ['/', '/admin', '/admin/outbox', '/admin/alerts/1']:
        assert client.get(path).status_code == 200
    assert post(client, '/admin/alerts/1/review').status_code == 302
    with app.app_context():
        assert db().execute('SELECT status FROM alerts').fetchone()[0] == 'reviewed'


def test_explanation_reconstruction(app):
    model = app.extensions['flow_model']
    explanation = model.predict(validate_flow(flow()))
    score = explanation['intercept'] + sum(t['log_odds_contribution'] for t in explanation['contributions'])
    assert np.isclose(1 / (1 + np.exp(-np.clip(score, -35, 35))), explanation['score'])


@pytest.mark.parametrize('value', [float('nan'), float('inf'), -1, True, '100', .5])
def test_invalid_packet_count(value):
    with pytest.raises(ValueError):
        validate_flow({**flow(), 'forward_packets': value})


def test_location_is_not_exact():
    assert location('127.0.0.1')['status'] == 'unavailable'
    assert location('8.8.8.8')['status'] == 'unavailable'


def test_zeek_adapter():
    record = {'id.orig_h': '192.0.2.1', 'id.resp_p': 443, 'duration': .3, 'orig_pkts': 10, 'resp_pkts': 9}
    result = zeek_flow(record)
    assert result['duration_seconds'] == .3
    assert result['collector'] == 'zeek-experimental'
    assert zeek_flow(record)['event_id'] == result['event_id']
    validate_flow(result)


def test_missing_model_fails_closed(tmp_path):
    app = create_app({'TESTING': True, 'INSTANCE': str(tmp_path), 'SENSOR_TOKEN': 'test-token'})
    assert app.test_client().post('/api/flows', json=flow(), headers={'Authorization': 'Bearer test-token'}).status_code == 503


def test_mail_failure_retries_without_marking_delivered(app):
    from security_app.app import queue_email
    app.config['MAIL_MODE'] = 'invalid-mode-for-test'
    with app.app_context():
        queue_email('user@example.test', 'test', 'test')
        db().commit()
    assert deliver(app) == 1
    with app.app_context():
        row = db().execute('SELECT * FROM notifications').fetchone()
        assert row['state'] == 'pending' and row['attempts'] == 1
        assert row['next_try'] > time.time()
    assert deliver(app) == 0


def test_account_privacy(app):
    client = app.test_client()
    for _ in range(10):
        post(client, '/login', email='user@example.test', password='wrong')
    post(client, '/login', email='unverified@example.test', password='long-demo-password')
    assert b'Repeated failed sign-ins' not in client.get('/account').data
    assert client.get('/admin/alerts/1').status_code == 403


def test_sampled_partitions_are_disjoint_and_preprocessing_train_only(tmp_path):
    import pandas as pd
    from security_app.train import COLUMNS, load_data, train
    source = tmp_path / 'csvs'
    source.mkdir()
    for i, name in enumerate(['Monday', 'Tuesday', 'Thursday', 'Friday']):
        records = []
        for j in range(40):
            label = 'BENIGN' if j < 20 else ('Web Attack XSS' if name == 'Thursday' else 'DoS Hulk')
            records.append([1000 * (i * 100 + j + 1), j + 1, i + 1, 80 + j, label])
        pd.DataFrame(records, columns=COLUMNS).to_csv(source / f'{name}-test.csv', index=False)
    output = tmp_path / 'trained'
    train(source, output, 100)
    partitions = pd.read_csv(output / 'partitions.csv')
    assert partitions.feature_hash.is_unique
    assert partitions.loc[partitions.partition.eq('train'), 'source'].str.startswith('Friday').sum() == 0
    frame, _ = load_data(source, 100)
    hashes = pd.util.hash_pandas_object(frame[FIELDS], index=False)
    train_hashes = set(partitions.loc[partitions.partition.eq('train'), 'feature_hash'])
    expected = np.log1p(frame.loc[hashes.isin(train_hashes), FIELDS].to_numpy(float)).mean(axis=0)
    assert np.allclose(FlowModel(output).model.mean_, expected)


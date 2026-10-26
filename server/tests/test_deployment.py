from classroom import create_app


def test_default_ignores_forwarded_identity(tmp_path):
    app = create_app({'TESTING': True, 'INSTANCE': str(tmp_path), 'TRUSTED_PROXY_HOPS': 0})
    @app.get('/test-address')
    def address():
        from flask import request
        return {'ip': request.remote_addr, 'secure': request.is_secure}
    result = app.test_client().get('/test-address', headers={'X-Forwarded-For': '198.51.100.9', 'X-Forwarded-Proto': 'https'})
    assert result.json == {'ip': '127.0.0.1', 'secure': False}


def test_explicit_single_trusted_proxy(tmp_path):
    app = create_app({'TESTING': True, 'INSTANCE': str(tmp_path), 'TRUSTED_PROXY_HOPS': 1})
    @app.get('/test-address')
    def address():
        from flask import request
        return {'ip': request.remote_addr, 'secure': request.is_secure, 'host': request.host}
    result = app.test_client().get('/test-address', headers={
        'X-Forwarded-For': 'forged, 198.51.100.9', 'X-Forwarded-Proto': 'https', 'X-Forwarded-Host': 'attacker.test'})
    assert result.json == {'ip': '198.51.100.9', 'secure': True, 'host': 'localhost'}


def test_sqlite_state_survives_app_restart(tmp_path):
    from security_app.app import db
    config = {'TESTING': True, 'INSTANCE': str(tmp_path)}
    app = create_app(config)
    with app.app_context():
        db().execute("INSERT INTO classroom_progress VALUES(9, '{}')")
        db().commit()
    second = create_app(config)
    assert app.secret_key == second.secret_key
    with second.app_context():
        assert db().execute('SELECT payload FROM classroom_progress WHERE user_id=9').fetchone()['payload'] == '{}'


def test_backup_command_is_readable_and_refuses_overwrite(tmp_path, monkeypatch):
    import sqlite3
    import sys
    import pytest
    from manage import main
    monkeypatch.setenv('SECURITY_INSTANCE', str(tmp_path / 'instance'))
    target = tmp_path / 'backup.sqlite3'
    monkeypatch.setattr(sys, 'argv', ['manage.py', 'backup', '--output', str(target)])
    main()
    with sqlite3.connect(target) as saved:
        assert saved.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        assert saved.execute("SELECT name FROM sqlite_master WHERE name='users'").fetchone()
    assert target.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        main()

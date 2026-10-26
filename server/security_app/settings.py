"""Local operator settings; secrets are never exposed through HTTP."""
import json
import os
from pathlib import Path

KEYS = {'SENSOR_TOKEN', 'WEBSITE_TOKEN', 'WEBSITE_ID', 'GEOIP_DB', 'MAIL_MODE', 'ADMIN_EMAIL',
        'SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_PASSWORD', 'SMTP_FROM', 'PUBLIC_URL', 'MODEL_DIR'}


def load_settings(instance):
    path = Path(instance) / 'settings.json'
    saved = json.loads(path.read_text()) if path.exists() else {}
    if not isinstance(saved, dict) or set(saved) - KEYS:
        raise ValueError('Invalid settings file')
    return {key: os.environ.get(key, value) for key, value in saved.items()} | {
        key: os.environ[key] for key in KEYS if key in os.environ}


def save_settings(instance, updates):
    if set(updates) - KEYS:
        raise ValueError('Unknown configuration key')
    path = Path(instance) / 'settings.json'
    saved = json.loads(path.read_text()) if path.exists() else {}
    saved.update(updates)
    temporary = path.with_suffix('.tmp')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(saved, stream, indent=2)
    os.replace(temporary, path)


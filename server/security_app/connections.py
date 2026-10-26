"""Read-only readiness report: configured is not the same as connected."""
import shutil
import time
from pathlib import Path


def status(app, db):
    last_flow = db().execute("SELECT MAX(created) FROM flows WHERE collector='zeek-experimental'").fetchone()[0]
    last_website = db().execute('SELECT MAX(created) FROM website_events WHERE site_id=?', (app.config.get('WEBSITE_ID'),)).fetchone()[0]
    smtp_ready = all(app.config.get(k) for k in ['SMTP_HOST', 'SMTP_FROM'])
    geo = app.config.get('GEOIP_DB')
    geo_status = 'not configured'
    if geo:
        try:
            import geoip2.database
            with geoip2.database.Reader(geo) as reader:
                geo_status = 'database readable: ' + reader.metadata().database_type
        except Exception:
            geo_status = 'configured path unreadable or invalid'
    return [
        {'component': 'Detector', 'configuration': app.extensions['flow_model'].metadata.get('algorithm', 'linear baseline') if app.extensions['flow_model'] else 'not trained',
         'evidence': 'Loaded locally; live-network accuracy is not established'},
        {'component': 'Website', 'configuration': app.config.get('WEBSITE_ID', 'not configured'),
         'evidence': ('Last event received ' + str(int(time.time() - last_website)) + ' seconds ago') if last_website else 'No website events received'},
        {'component': 'Website credential', 'configuration': 'configured' if app.config.get('WEBSITE_TOKEN') else 'missing', 'evidence': 'Server-side secret only; never embed in browser code'},
        {'component': 'Network collector', 'configuration': 'sensor token configured' if app.config.get('SENSOR_TOKEN') else 'sensor token missing',
         'evidence': ('Last Zeek event received ' + str(int(time.time() - last_flow)) + ' seconds ago; source authenticity depends on sensor') if last_flow else 'No Zeek telemetry received; CSV replay does not count'},
        {'component': 'Zeek on this machine', 'configuration': 'installed' if shutil.which('zeek') else 'not installed', 'evidence': 'A collector may instead run on the authorized server'},
        {'component': 'Email', 'configuration': app.config['MAIL_MODE'], 'evidence': 'SMTP settings present; delivery unverified' if smtp_ready else 'SMTP settings incomplete; local outbox is available'},
        {'component': 'IP location', 'configuration': geo_status, 'evidence': 'Approximate network location only; no exact person tracking'}]


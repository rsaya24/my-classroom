"""Single-host research deployment. TLS terminates at the hosting proxy."""
import os

bind = os.environ.get('BIND', '127.0.0.1:5001')
workers = 1
threads = 4
timeout = 120
accesslog = None  # Avoid retaining verification tokens in URL access logs.
errorlog = '-'
capture_output = True
umask = 0o077
# Ignore forwarded scheme headers unless explicitly validated by the app's proxy setup.
forwarded_allow_ips = ''

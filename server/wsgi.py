"""Production WSGI entry point; use a persistent SECURITY_INSTANCE directory."""
from classroom import create_app

app = create_app()

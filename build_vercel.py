"""Copy only public UI assets to Vercel's CDN; never copy private instance data."""
import shutil
from pathlib import Path

root = Path(__file__).resolve().parent
public = root / 'public'
public.mkdir(exist_ok=True)
for source, target in [(root / 'client/dist/assets', public / 'assets'),
                       (root / 'server/security_app/static', public / 'static')]:
    shutil.copytree(source, target, dirs_exist_ok=True)
favicon = root / 'client/public/favicon.svg'
if favicon.exists():
    shutil.copy2(favicon, public / 'favicon.svg')

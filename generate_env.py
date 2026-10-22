"""Create .env from .env.example with freshly generated random secrets. Never overwrites an existing .env."""
import re
import secrets
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
target, template = root / ".env", root / ".env.example"
if target.exists():
    print(".env already exists; leaving it untouched.")
    sys.exit(0)
text = template.read_text()
replacements = {
    "NEXOPS_SECRET_KEY": secrets.token_urlsafe(48),
    "POSTGRES_PASSWORD": secrets.token_urlsafe(24),
    "GRAFANA_ADMIN_PASSWORD": secrets.token_urlsafe(18),
}
for key, value in replacements.items():
    text = re.sub(rf"^{key}=.*$", f"{key}={value}", text, flags=re.M)
target.write_text(text)
print("Created .env with generated secrets (kept out of git).")

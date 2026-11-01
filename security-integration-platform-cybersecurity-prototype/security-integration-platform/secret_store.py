"""Encrypted secret storage (FR-6). Secrets are looked up in the vault first, then in environment variables.
The vault key comes from SECURITY_VAULT_KEY or a 0600 key file OUTSIDE the project (~/.security_platform)."""
import os, threading
from pathlib import Path
from cryptography.fernet import Fernet
from security_engine.secrets import SecretVault
from security_engine.http_safety import validate_secret_env

_lock = threading.Lock()

def home() -> Path:
    return Path(os.environ.get("PLATFORM_HOME") or Path.home() / ".security_platform")

def _key() -> bytes:
    k = os.environ.get("SECURITY_VAULT_KEY")
    if k: return k.encode()
    d = home(); d.mkdir(parents=True, exist_ok=True)
    try: d.chmod(0o700)
    except OSError: pass
    kf = d / "vault.key"
    if not kf.exists():
        try:
            fd = os.open(kf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f: f.write(Fernet.generate_key())
        except FileExistsError: pass
    return kf.read_bytes().strip()

def _vault() -> SecretVault:
    return SecretVault(home() / "vault.enc", _key())

def get_secret(name: str) -> str | None:
    validate_secret_env(name)
    with _lock:
        try: return _vault().get(name)
        except KeyError: return os.environ.get(name) or None

def is_set(name: str) -> bool:
    try: return bool(get_secret(name))
    except ValueError: return False

def set_secret(name: str, value: str) -> None:
    validate_secret_env(name)
    with _lock: _vault().set(name, value)

def delete_secret(name: str) -> None:
    validate_secret_env(name)
    with _lock: _vault().delete(name)

def list_names() -> list[str]:
    with _lock: return _vault().names()

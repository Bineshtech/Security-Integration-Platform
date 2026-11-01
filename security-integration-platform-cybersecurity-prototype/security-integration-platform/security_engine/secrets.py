"""Encrypted local secret vault. Keep the master key outside the project directory."""
from __future__ import annotations
import base64, os
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken

class SecretVault:
    def __init__(self, vault_path: str | Path, key: bytes | str | None = None):
        self.path = Path(vault_path)
        raw = key or os.environ.get("SECURITY_VAULT_KEY")
        if raw is None:
            raise ValueError("Set SECURITY_VAULT_KEY or pass a key from the OS credential store.")
        if isinstance(raw, str): raw = raw.encode()
        try: self.fernet = Fernet(raw)
        except Exception as exc: raise ValueError("Invalid Fernet vault key.") from exc
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_bytes(b"")
            try: self.path.chmod(0o600)
            except OSError: pass

    def _read(self) -> dict[str, str]:
        import json
        if not self.path.exists() or not self.path.stat().st_size: return {}
        try: return json.loads(self.fernet.decrypt(self.path.read_bytes()).decode())
        except (InvalidToken, ValueError) as exc: raise ValueError("Vault authentication failed; key may be wrong or file altered.") from exc

    def _write(self, values: dict[str, str]) -> None:
        import json
        temp = self.path.with_suffix(self.path.suffix + ".tmp")
        temp.write_bytes(self.fernet.encrypt(json.dumps(values).encode()))
        try: temp.chmod(0o600)
        except OSError: pass
        os.replace(temp, self.path)
        try: self.path.chmod(0o600)
        except OSError: pass

    def set(self, name: str, value: str) -> None:
        if not name or not isinstance(value, str) or not value: raise ValueError("Secret name and value are required.")
        data = self._read(); data[name] = value; self._write(data)

    def get(self, name: str) -> str:
        try: return self._read()[name]
        except KeyError as exc: raise KeyError(f"Secret not found: {name}") from exc

    def names(self) -> list[str]:
        return sorted(self._read())

    def delete(self, name: str) -> None:
        data = self._read()
        if name not in data: raise KeyError(name)
        del data[name]; self._write(data)

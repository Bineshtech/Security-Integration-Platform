"""Small dependency-free password and signed-session primitives for local deployments."""
from __future__ import annotations
import base64, hashlib, hmac, json, os, secrets, time

class AuthManager:
    def __init__(self, signing_key: str | bytes, iterations: int = 310_000):
        self.key = signing_key.encode() if isinstance(signing_key, str) else signing_key
        if len(self.key) < 32: raise ValueError("Signing key must be at least 32 bytes.")
        self.iterations = iterations; self.revoked: set[str] = set()

    def hash_password(self, password: str) -> str:
        if len(password) < 12: raise ValueError("Password must be at least 12 characters.")
        salt = os.urandom(16); digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, self.iterations)
        return f"pbkdf2_sha256${self.iterations}${base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(digest).decode()}"

    def verify_password(self, password: str, encoded: str) -> bool:
        try:
            algo, rounds, salt, expected = encoded.split("$")
            if algo != "pbkdf2_sha256": return False
            actual = hashlib.pbkdf2_hmac("sha256", password.encode(), base64.urlsafe_b64decode(salt), int(rounds))
            return hmac.compare_digest(actual, base64.urlsafe_b64decode(expected))
        except Exception: return False

    def issue_session(self, subject: str, roles: list[str], ttl_seconds: int = 1800) -> str:
        if not isinstance(roles, list) or not all(isinstance(r, str) for r in roles): raise ValueError("roles must be a list of strings.")
        if ttl_seconds < 1 or ttl_seconds > 86400: raise ValueError("Session TTL must be 1..86400 seconds.")
        payload = {"sub": subject, "roles": roles, "exp": int(time.time()) + ttl_seconds, "jti": secrets.token_hex(12)}
        body = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).rstrip(b"=")
        sig = hmac.new(self.key, body, hashlib.sha256).digest()
        return body.decode() + "." + base64.urlsafe_b64encode(sig).rstrip(b"=").decode()

    def verify_session(self, token: str) -> dict:
        try:
            body, signature = token.split(".", 1)
            expected = hmac.new(self.key, body.encode(), hashlib.sha256).digest()
            supplied = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
            if not hmac.compare_digest(expected, supplied): raise ValueError("Invalid session signature.")
            payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
            if int(payload["exp"]) <= time.time(): raise ValueError("Session expired.")
            if payload.get("jti") in self.revoked: raise ValueError("Session revoked.")
            if not isinstance(payload.get("roles"), list) or not isinstance(payload.get("sub"), str): raise ValueError("Malformed session.")
            return payload
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc: raise ValueError("Invalid or expired session.") from exc

    def revoke_session(self, token: str) -> None:
        self.revoked.add(self.verify_session(token)["jti"])

    @staticmethod
    def require_role(session: dict, role: str) -> None:
        roles = session.get("roles")
        if not isinstance(roles, list) or role not in roles: raise PermissionError("Insufficient permissions.")

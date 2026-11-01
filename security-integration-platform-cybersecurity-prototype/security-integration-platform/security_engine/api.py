"""Rate limiting and signed webhook verification."""
import hashlib, hmac, threading, time
from collections import defaultdict, deque

class InMemoryRateLimiter:
    """Single-process limiter; use a shared store (e.g. Redis) for multi-worker deployments."""
    def __init__(self, limit: int = 60, window_seconds: int = 60, max_keys: int = 10_000):
        self.limit, self.window, self.max_keys = limit, window_seconds, max_keys
        self.hits = defaultdict(deque); self.lock = threading.Lock()
    def _purge(self, now: float) -> None:
        for k in [k for k, q in self.hits.items() if not q or q[-1] <= now - self.window]: del self.hits[k]
    def allow(self, key: str, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        with self.lock:
            if key not in self.hits and len(self.hits) >= self.max_keys:
                self._purge(now)
                if len(self.hits) >= self.max_keys: return False  # fail closed under key-flood
            q = self.hits[key]
            while q and q[0] <= now - self.window: q.popleft()
            if len(q) >= self.limit: return False
            q.append(now); return True

class ReplayGuard:
    def __init__(self, ttl: int = 300, max_entries: int = 100_000): self.ttl=ttl; self.max=max_entries; self.seen={}; self.lock=threading.Lock()
    def accept(self, nonce: str, now: float) -> bool:
        with self.lock:
            self.seen = {k:v for k,v in self.seen.items() if v > now}
            if nonce in self.seen or len(self.seen) >= self.max: return False
            self.seen[nonce] = now + self.ttl; return True

def verify_webhook(body: bytes, timestamp: str, nonce: str, signature: str, secret: str | bytes, *, replay_guard: ReplayGuard, tolerance_seconds: int = 300, now: float | None = None) -> bool:
    now = time.time() if now is None else now
    try: ts = int(timestamp)
    except (TypeError, ValueError): return False
    if not isinstance(replay_guard, ReplayGuard): raise TypeError("replay_guard is required.")
    if abs(now - ts) > tolerance_seconds or not nonce or len(nonce) > 128: return False
    key = secret.encode() if isinstance(secret, str) else secret
    message = timestamp.encode() + b"." + nonce.encode() + b"." + body
    expected = hmac.new(key, message, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature.lower()): return False
    return replay_guard.accept(nonce, now)

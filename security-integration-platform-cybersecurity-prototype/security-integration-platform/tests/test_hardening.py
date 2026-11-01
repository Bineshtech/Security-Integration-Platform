"""Regression tests for every flaw confirmed in the original engine. Stdlib unittest: run with
`python -m unittest discover -s tests -p "test_hardening.py"` (also collected by pytest)."""
import hashlib, hmac, os, sqlite3, sys, tempfile, time, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from security_engine import load_safe_yaml, validate_external_url, InMemoryRateLimiter, verify_webhook, execute_tenant_query, AuthManager
from security_engine.api import ReplayGuard
from security_engine.http_safety import *

class Net(unittest.TestCase):
    def test_embedded_ipv4_blocked(self):
        for u in ["https://[64:ff9b::7f00:1]/", "https://[64:ff9b::a00:1]/", "https://[::ffff:127.0.0.1]/", "https://[2002:7f00:1::1]/",
                  "https://[2001:0:4136:e378:8000:63bf:3fff:fdd2]/", "https://127.0.0.1/", "https://169.254.169.254/", "https://localhost/"]:
            with self.assertRaises(ValueError, msg=u): validate_external_url(u)
    def test_http_and_creds_blocked(self):
        for u in ["http://8.8.8.8/", "https://user:pw@8.8.8.8/"]:
            with self.assertRaises(ValueError): validate_external_url(u)
        self.assertEqual(validate_external_url("https://8.8.8.8/x"), "https://8.8.8.8/x")

class Http(unittest.TestCase):
    def test_absolute_endpoint_rejected(self):
        for p in ["https://evil.example/steal", "//evil.example/x", "../x", "a/../../x", "x\\y", "a\nb"]:
            with self.assertRaises(ValueError, msg=p): safe_join("https://api.vendor.com/v1", p)
        self.assertEqual(safe_join("https://api.vendor.com/v1", "/users?x=1"), "https://api.vendor.com/v1/users?x=1")
    def test_pagination_origin_lock(self):
        with self.assertRaises(ValueError): follow_next_url("https://api.vendor.com/a", "https://evil.example/x")
        self.assertEqual(follow_next_url("https://api.vendor.com/a", "/a?page=2"), "https://api.vendor.com/a?page=2")
    def test_retry_after_clamped(self):
        self.assertEqual(clamp_retry_after("999999999"), 60.0); self.assertEqual(clamp_retry_after("inf"), 60.0)
        self.assertEqual(clamp_retry_after("nan"), 60.0); self.assertEqual(clamp_retry_after(-5), 0.0); self.assertIsNone(clamp_retry_after("abc"))
    def test_path_params(self):
        for v in ["..", ".", "", "a/b", "a\x00", "x" * 300]:
            with self.assertRaises(ValueError): safe_path_param(v)
        self.assertEqual(safe_path_param("host-1"), "host-1")
    def test_secret_env_and_headers(self):
        for n in ["PLATFORM_SIGNING_KEY", "PATH", "AWS_SECRET_ACCESS_KEY", "connector_x", ""]:
            with self.assertRaises(ValueError): validate_secret_env(n)
        validate_secret_env("CONNECTOR_GITHUB_TOKEN")
        for h in ["Host", "Content-Length", "X Bad", "a:b", "Cookie"]:
            with self.assertRaises(ValueError): validate_header_name(h)
        validate_header_name("X-API-Key")

class Yaml(unittest.TestCase):
    def test_alias_bomb_and_depth(self):
        bomb = "a: &a [x,x,x,x]\nb: &b [*a,*a,*a,*a]\nc: *b\n"
        with self.assertRaises(ValueError): load_safe_yaml(bomb)
        with self.assertRaises(ValueError): load_safe_yaml("a: " + "[" * 40 + "]" * 40)
        with self.assertRaises(ValueError): load_safe_yaml("x: 1\nx: 2")
        with self.assertRaises(ValueError): load_safe_yaml('!!python/object/apply:os.system ["id"]')
        self.assertEqual(load_safe_yaml("a: 1\nb: [1,2]")["a"], 1)

class Tenant(unittest.TestCase):
    def setUp(self):
        self.c = sqlite3.connect(":memory:"); self.c.execute("create table r(tenant_id text, v text)")
        self.c.executemany("insert into r values (?,?)", [("A", "a1"), ("B", "b1")])
    def test_scoped(self):
        self.assertEqual(execute_tenant_query(self.c, "select v from r where tenant_id = :tenant_id", {}, "A").fetchall(), [("a1",)])
    def test_widening_rejected(self):
        for q in ["select v from r where tenant_id != :tenant_id", "select v from r where tenant_id <> :tenant_id",
                  "select v from r where tenant_id = :tenant_id or 1=1", "select v from r where tenant_id = :tenant_id union select v from r",
                  "select v from r where tenant_id = :tenant_id; delete from r", "select v from r -- tenant_id = :tenant_id",
                  "select v from r where /* tenant_id = :tenant_id */ 1=1", "select v from r", "drop table r",
                  "select v from r where tenant_id = :tenant_id and tenant_id like '%'"]:
            with self.assertRaises(ValueError, msg=q): execute_tenant_query(self.c, q, {}, "A")
        with self.assertRaises(ValueError): execute_tenant_query(self.c, "select v from r where tenant_id = :tenant_id", {"tenant_id": "B"}, "A")

class Misc(unittest.TestCase):
    def test_rate_limiter_bounded(self):
        rl = InMemoryRateLimiter(1, 60, max_keys=5)
        for i in range(5): self.assertTrue(rl.allow(f"k{i}", now=100))
        self.assertFalse(rl.allow("flood", now=101)); self.assertLessEqual(len(rl.hits), 5)
        self.assertTrue(rl.allow("later", now=500))  # expired keys purged
    def test_webhook_requires_guard(self):
        body, ts, n, sec = b"{}", "1000", "n", b"s"
        sig = hmac.new(sec, ts.encode() + b"." + n.encode() + b"." + body, hashlib.sha256).hexdigest()
        with self.assertRaises(TypeError): verify_webhook(body, ts, n, sig, sec, now=1000)
        g = ReplayGuard(); self.assertTrue(verify_webhook(body, ts, n, sig, sec, now=1000, replay_guard=g))
        self.assertFalse(verify_webhook(body, ts, n, sig, sec, now=1000, replay_guard=g))
    def test_roles_string_not_substring(self):
        a = AuthManager("k" * 32)
        with self.assertRaises(ValueError): a.issue_session("x", "administrator")
        with self.assertRaises(PermissionError): a.require_role({"roles": "administrator"}, "admin")
    def test_session_revocation(self):
        a = AuthManager("k" * 32); t = a.issue_session("x", ["viewer"]); a.verify_session(t); a.revoke_session(t)
        with self.assertRaises(ValueError): a.verify_session(t)

class Approvals(unittest.TestCase):
    def setUp(self):
        import approval_manager as am
        self.am = am; am.DB_PATH = Path(tempfile.mkdtemp()) / "t.db"
    def test_flow(self):
        am = self.am; p = {"id": "h1"}
        r = am.request_approval("edr", "isolate", "bob", p)
        with self.assertRaises(PermissionError): am.decide_approval(r["approval_id"], "bob", "APPROVED")   # no self-approval
        self.assertFalse(am.verify_approval(r["approval_id"], "edr", "isolate", p))                        # still pending
        am.decide_approval(r["approval_id"], "carol", "APPROVED")
        self.assertFalse(am.verify_approval(r["approval_id"], "edr", "isolate", {"id": "OTHER"}))        # params bound
        self.assertFalse(am.verify_approval(r["approval_id"], "edr", "other", p))                         # action bound
        self.assertTrue(am.verify_approval(r["approval_id"], "edr", "isolate", p))
        self.assertFalse(am.verify_approval(r["approval_id"], "edr", "isolate", p))                       # single use
        self.assertFalse(am.verify_approval("totally-fake", "edr", "isolate", p))

if __name__ == "__main__": unittest.main()

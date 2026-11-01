"""End-to-end API tests (needs: pip install -r requirements.txt). Run: pytest -q tests/test_api.py"""
import os, sys, tempfile
from pathlib import Path
os.environ["PLATFORM_DB_PATH"] = str(Path(tempfile.mkdtemp()) / "t.db")
os.environ["PLATFORM_SIGNING_KEY"] = "s" * 48
os.environ["PLATFORM_ADMIN_USER"] = "admin"; os.environ["PLATFORM_ADMIN_PASSWORD"] = "correct-horse-battery"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import pytest
from fastapi.testclient import TestClient
import app as platform

client = TestClient(platform.app)

def login(u="admin", p="correct-horse-battery"):
    r = client.post("/auth/login", json={"username": u, "password": p}); return r

def hdr(token): return {"Authorization": f"Bearer {token}"}

@pytest.fixture(scope="module")
def admin():
    return login().json()["token"]

def make_user(name, role):
    with platform.db_connection() as c:
        c.execute("INSERT OR REPLACE INTO platform_accounts VALUES (?,?,?,?)", (name, platform.auth_manager.hash_password("another-long-password"), role, "now"))
    return login(name, "another-long-password").json()["token"]

def test_unauthenticated_routes_are_closed():
    for m, p in [("get", "/records/user"), ("get", "/runs"), ("get", "/connectors"), ("post", "/sync/github"), ("get", "/invalid-records"),
                 ("post", "/config/validate"), ("get", "/approvals"), ("post", "/actions/prepare"), ("get", "/health/connectors")]:
        assert getattr(client, m)(p).status_code in (401, 422), p
    assert client.get("/health").json() == {"status": "ok"}      # liveness only, no connector detail

def test_security_headers_and_no_docs():
    r = client.get("/health")
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    assert client.get("/docs").status_code == 404

def test_login_bad_password_and_lockout():
    assert login("admin", "wrong-password-1").status_code == 401
    codes = [login("ghost", "x").status_code for _ in range(8)]
    assert 429 in codes

def test_roles_enforced():
    v = make_user("vera", "viewer")
    assert client.get("/runs", headers=hdr(v)).status_code == 200
    assert client.post("/sync/github", headers=hdr(v)).status_code == 403
    assert client.get("/invalid-records", headers=hdr(v)).status_code == 403
    assert client.post("/approvals/x/decision", json={"decision": "APPROVED"}, headers=hdr(v)).status_code == 403

def test_logout_revokes_token():
    t = login().json()["token"]
    assert client.get("/auth/me", headers=hdr(t)).status_code == 200
    client.post("/auth/logout", headers=hdr(t))
    assert client.get("/auth/me", headers=hdr(t)).status_code == 401

def test_bad_names_rejected(admin):
    assert client.get("/records/user%27%20OR%201=1", headers=hdr(admin)).status_code in (400, 404, 422)
    assert client.post("/sync/..%2Fsecrets", headers=hdr(admin)).status_code in (400, 404)

def test_config_rejects_unsafe_env_and_aliases(admin):
    base = "name: x\nbase_url: https://api.vendor.com\nendpoint: {path: /a}\nmapping: {entity: user}\nauth: {type: bearer, secret: %s}\n"
    assert client.post("/config/validate", json={"config": base % "PLATFORM_SIGNING_KEY"}, headers=hdr(admin)).status_code == 422
    assert client.post("/config/validate", json={"config": base % "CONNECTOR_TOKEN"}, headers=hdr(admin)).status_code == 200
    assert client.post("/config/validate", json={"config": "a: &a [1]\nb: *a"}, headers=hdr(admin)).status_code == 422
    assert client.post("/config/validate", json={"config": base.replace("https", "http") % "CONNECTOR_T"}, headers=hdr(admin)).status_code == 422

def test_approval_flow_and_separation_of_duties(admin):
    analyst = make_user("ann", "analyst")
    params = {"host_id": "h1"}
    r = client.post("/approvals", json={"connector_name": "approval_test_fixture", "action_name": "isolate_host", "parameters": params}, headers=hdr(analyst))
    aid = r.json()["approval_id"]
    prep = lambda tok, a=aid, p=params: client.post("/actions/prepare", json={"connector_name": "approval_test_fixture", "action_name": "isolate_host", "parameters": p, "approval_id": a}, headers=hdr(tok)).json()
    assert prep(analyst, None)["ready"] is False                                   # no approval id
    assert prep(analyst, "fake-approval")["ready"] is False                        # fake id
    assert prep(analyst)["ready"] is False                                         # still pending
    assert client.post(f"/approvals/{aid}/decision", json={"decision": "APPROVED"}, headers=hdr(analyst)).status_code == 403
    assert client.post(f"/approvals/{aid}/decision", json={"decision": "APPROVED"}, headers=hdr(admin)).status_code == 200
    assert prep(analyst, p={"host_id": ".."})["ready"] is False                    # params bound + '..' rejected
    ok = prep(analyst); assert ok["ready"] and not ok["execution_performed"] and ok["requested_by"] == "ann"
    assert prep(analyst)["ready"] is False                                         # single use

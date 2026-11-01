import hashlib, hmac, json, os, sqlite3, tempfile, time
from pathlib import Path
import pytest
from cryptography.fernet import Fernet
from security_engine import SecretVault, AuthManager, load_safe_yaml, validate_external_url, InMemoryRateLimiter, verify_webhook, execute_tenant_query, run_restricted
from security_engine.api import ReplayGuard

def test_secret_vault_roundtrip_and_wrong_key(tmp_path):
    key = Fernet.generate_key(); vault = SecretVault(tmp_path/'vault.enc', key); vault.set('github', 'top-secret')
    assert vault.get('github') == 'top-secret'
    assert b'top-secret' not in (tmp_path/'vault.enc').read_bytes()
    with pytest.raises(ValueError): SecretVault(tmp_path/'vault.enc', Fernet.generate_key()).get('github')

def test_password_and_signed_session():
    auth=AuthManager('k'*32); hashed=auth.hash_password('correct horse battery')
    assert auth.verify_password('correct horse battery', hashed)
    assert not auth.verify_password('wrong password', hashed)
    token=auth.issue_session('alice',['admin']); session=auth.verify_session(token)
    assert session['sub']=='alice'; auth.require_role(session,'admin')
    with pytest.raises(PermissionError): auth.require_role(session,'viewer')
    with pytest.raises(ValueError): auth.verify_session(token[:-1]+'x')

def test_yaml_safe_and_duplicate_key():
    assert load_safe_yaml('name: demo\nitems:\n - one')['name']=='demo'
    with pytest.raises(ValueError): load_safe_yaml('x: 1\nx: 2')
    with pytest.raises(ValueError): load_safe_yaml('!!python/object/apply:os.system ["echo bad"]')
    with pytest.raises(ValueError): load_safe_yaml('x: 1', max_bytes=2)

def test_url_blocks_private_and_non_https(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(None, None, None, None, ("93.184.216.34", 443))])
    with pytest.raises(ValueError): validate_external_url('http://example.com')
    with pytest.raises(ValueError): validate_external_url('https://127.0.0.1')
    with pytest.raises(ValueError): validate_external_url('https://localhost')
    assert validate_external_url('https://example.com/api') == 'https://example.com/api'

def test_rate_limit():
    limiter=InMemoryRateLimiter(2, 60)
    assert limiter.allow('ip', now=100); assert limiter.allow('ip', now=101)
    assert not limiter.allow('ip', now=102); assert limiter.allow('ip', now=161)

def test_webhook_signature_timestamp_and_replay():
    body=b'{"event":"sync"}'; ts=str(1000); nonce='n1'; secret=b'secret'
    msg=ts.encode()+b'.'+nonce.encode()+b'.'+body
    sig=hmac.new(secret,msg,hashlib.sha256).hexdigest(); guard=ReplayGuard()
    assert verify_webhook(body,ts,nonce,sig,secret,now=1000,replay_guard=guard)
    assert not verify_webhook(body,ts,nonce,sig,secret,now=1000,replay_guard=guard)
    assert not verify_webhook(body,ts,nonce,sig,secret,now=2000,replay_guard=ReplayGuard())
    with pytest.raises(TypeError): verify_webhook(body,ts,nonce,sig,secret,now=1000)  # guard is mandatory

def test_tenant_query_requires_scope_and_binds_value():
    conn=sqlite3.connect(':memory:'); conn.execute('create table records(tenant_id text, value text)')
    conn.executemany('insert into records values (?,?)',[('a','A'),('b','B')])
    rows=execute_tenant_query(conn,'select value from records where value != :v and tenant_id = :tenant_id',{'v':'none'},'a').fetchall()
    assert rows == [('A',)]
    for bad in ['select * from records','select value from records where tenant_id != :tenant_id',
                'select value from records where tenant_id = :tenant_id or 1=1','select value from records where tenant_id = :tenant_id -- x']:
        with pytest.raises(ValueError): execute_tenant_query(conn,bad,{},'a')

def test_restricted_process():
    result=run_restricted([os.sys.executable,'-c','print("safe")'],timeout=5)
    assert result.returncode==0 and result.stdout.strip()=='safe'
    with pytest.raises(ValueError): run_restricted('echo unsafe')

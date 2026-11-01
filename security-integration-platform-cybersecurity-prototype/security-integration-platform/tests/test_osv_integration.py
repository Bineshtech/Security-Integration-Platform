import app


class FakeResponse:
    def json(self):
        return {
            "vulns": [{
                "id": "GHSA-test-1234",
                "summary": "Test advisory",
                "details": "A test-only advisory description",
                "modified": "2026-01-01T00:00:00Z",
                "affected": [{"ecosystem_specific": {"severity": "HIGH"}}],
                "references": [],
            }]
        }


def test_osv_query_normalizes_and_saves(monkeypatch):
    calls = {}
    saved = []
    monkeypatch.setattr(app, "validate_external_url", lambda _url: None)

    def fake_request(client, method, url, **kwargs):
        calls.update(method=method, url=url, **kwargs)
        return FakeResponse()

    monkeypatch.setattr(app, "request_with_retries", fake_request)
    monkeypatch.setattr(app, "save_record", lambda source, entity, record: saved.append((source, entity, record)))

    result = app.query_osv_package(
        app.OSVPackageQuery(package_name="fastapi", ecosystem="PyPI", version="0.115.0"),
        {"sub": "test", "roles": ["analyst"]},
    )

    assert calls["method"] == "POST"
    assert calls["url"] == "https://api.osv.dev/v1/query"
    assert calls["json_body"]["package"] == {"name": "fastapi", "ecosystem": "PyPI"}
    assert result["vulnerabilities_found"] == 1
    assert result["records_saved"] == 1
    assert saved[0][0:2] == ("osv", "vulnerability")
    assert saved[0][2]["id"] == "GHSA-test-1234"
    assert saved[0][2]["severity"] == "HIGH"

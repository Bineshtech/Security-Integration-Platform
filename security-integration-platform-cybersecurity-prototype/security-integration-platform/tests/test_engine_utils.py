import os, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from engine_utils import *

class T(unittest.TestCase):
    def test_schedule(self):
        self.assertEqual(parse_schedule("15m"), 900); self.assertEqual(parse_schedule("every 2 hours"), 7200)
        self.assertEqual(parse_schedule("45 seconds"), 45); self.assertIsNone(parse_schedule(None)); self.assertIsNone(parse_schedule(""))
        for bad in ["often", "5s", "0m", "99d", "m15"]:
            with self.assertRaises(ValueError, msg=bad): parse_schedule(bad)
    def test_dates(self):
        self.assertEqual(convert_date(1700000000), "2023-11-14T22:13:20+00:00")
        self.assertEqual(convert_date("1700000000000"), "2023-11-14T22:13:20+00:00")
        self.assertEqual(convert_date("2024-05-01T10:00:00Z"), "2024-05-01T10:00:00+00:00")
        self.assertEqual(convert_date("2024-05-01T10:00:00.000"), "2024-05-01T10:00:00+00:00")
        self.assertEqual(convert_date("Wed, 01 May 2024 10:00:00 GMT"), "2024-05-01T10:00:00+00:00")
        self.assertEqual(convert_date("01/05/2024 10:00", "%d/%m/%Y %H:%M"), "2024-05-01T10:00:00+00:00")
        self.assertIsNone(convert_date(None)); self.assertIsNone(convert_date(""))
        for bad in ["yesterday-ish", True, {"a": 1}]:
            with self.assertRaises(ValueError): convert_date(bad)
    def test_resolve(self):
        g = lambda r, p: r.get(p)
        r = {"lastLogin": 1700000000, "n": "5", "e": ""}
        self.assertEqual(resolve_field(r, "n", g), "5")
        self.assertEqual(resolve_field(r, {"value": "x"}, g), "x")
        self.assertEqual(resolve_field(r, {"path": "lastLogin", "convert": "date"}, g), "2023-11-14T22:13:20+00:00")
        self.assertEqual(resolve_field(r, {"path": "e", "default": "none"}, g), "none")
        self.assertEqual(resolve_field(r, {"path": "n", "convert": "int"}, g), 5)
        self.assertIsNone(resolve_field(r, {"path": "missing", "convert": "date"}, g))
        with self.assertRaises(ValueError): resolve_field({"d": "garbage"}, {"path": "d", "convert": "date"}, g)
    def test_normalize(self):
        raw = {"name": "x", "vendor": None, "auth": {"type": "bearer", "secret_env": "CONNECTOR_T", "username_env": None, "header_name": "Authorization"},
               "pagination": {"strategy": "offset", "offset_param": "offset", "next_path": None}, "endpoint": {"path": "/a", "body": None, "headers": {}}}
        n = normalize_config(raw)
        self.assertEqual(n["auth"], {"type": "bearer", "secret": "CONNECTOR_T", "header": "Authorization"})
        self.assertEqual(n["pagination"], {"type": "offset", "start_param": "offset"})
        self.assertNotIn("body", n["endpoint"]); self.assertNotIn("vendor", n); self.assertIn("strategy", raw["pagination"])

class Vault(unittest.TestCase):
    def test_vault_roundtrip_and_env_fallback(self):
        os.environ["PLATFORM_HOME"] = tempfile.mkdtemp(); os.environ.pop("SECURITY_VAULT_KEY", None)
        import secret_store as s
        self.assertFalse(s.is_set("CONNECTOR_A"))
        s.set_secret("CONNECTOR_A", "tok-123"); self.assertEqual(s.get_secret("CONNECTOR_A"), "tok-123")
        self.assertEqual(s.list_names(), ["CONNECTOR_A"])
        self.assertNotIn(b"tok-123", (Path(os.environ["PLATFORM_HOME"]) / "vault.enc").read_bytes())
        self.assertEqual(oct((Path(os.environ["PLATFORM_HOME"]) / "vault.key").stat().st_mode & 0o777), "0o600")
        os.environ["CONNECTOR_B"] = "from-env"; self.assertEqual(s.get_secret("CONNECTOR_B"), "from-env")
        s.delete_secret("CONNECTOR_A"); self.assertFalse(s.is_set("CONNECTOR_A"))
        with self.assertRaises(ValueError): s.set_secret("PATH", "x")
        with self.assertRaises(ValueError): s.get_secret("PLATFORM_SIGNING_KEY")

if __name__ == "__main__": unittest.main()

"""Optional one-time cleanup of records/runs from removed demo connectors.

Preview by default. Run with --apply to delete only the named demo-source rows.
"""
import argparse
import os
import sqlite3
from pathlib import Path

DB_PATH = Path(os.environ.get("PLATFORM_DB_PATH") or Path(__file__).resolve().parent / "integration_platform.db")
DEMO_SOURCES = ("jsonplaceholder_test", "sample_security_connector", "automatic_security_connector")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="commit deletion; without this flag only show counts")
    args = parser.parse_args()
    if not DB_PATH.exists():
        print(f"No database found at {DB_PATH}; nothing to clean.")
        return
    placeholders = ",".join("?" for _ in DEMO_SOURCES)
    with sqlite3.connect(DB_PATH) as db:
        counts = {}
        for table in ("records", "runs", "invalid_records"):
            try:
                counts[table] = db.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE source IN ({placeholders})", DEMO_SOURCES
                ).fetchone()[0]
            except sqlite3.OperationalError:
                counts[table] = 0
        print("Demo rows found:", counts)
        if not args.apply:
            print("Preview only. Re-run with --apply to delete these demo rows.")
            return
        for table in ("records", "runs", "invalid_records"):
            try:
                db.execute(f"DELETE FROM {table} WHERE source IN ({placeholders})", DEMO_SOURCES)
            except sqlite3.OperationalError:
                pass
        db.commit()
        print("Deleted demo-source rows.")

if __name__ == "__main__":
    main()

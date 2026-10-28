"""Read-only view of the SQLite database for the 'Stored data' dashboard page."""
from __future__ import annotations

import os

from .database import Database

TABLES = ("devices", "scans", "ports", "findings", "traffic_sessions")   # fixed list: nothing the user types reaches SQL


def build_data(db: Database, limit: int = 25) -> dict:
    limit = max(1, min(int(limit), 100))
    tables = []
    for name in TABLES:
        cols = [r["name"] for r in db.conn.execute(f"PRAGMA table_info({name})")]
        count = db.conn.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
        rows = []
        for r in db.conn.execute(f"SELECT * FROM {name} ORDER BY id DESC LIMIT ?", (limit,)):
            row = []
            for c in cols:
                v = r[c]
                if isinstance(v, str) and len(v) > 120:
                    v = v[:117] + "..."
                row.append(v)
            rows.append(row)
        tables.append({"name": name, "columns": cols, "count": count, "rows": rows})
    size = os.path.getsize(db.path) if db.path != ":memory:" and os.path.exists(db.path) else 0
    return {"tables": tables, "path": db.path, "size": size, "limit": limit}
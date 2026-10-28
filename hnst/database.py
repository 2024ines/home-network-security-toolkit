"""SQLite storage: device inventory, scan history, ports, findings, traffic."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

from .models import Device, Finding, HostResult, PortInfo

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT UNIQUE NOT NULL,          -- MAC when known, otherwise 'ip:<addr>'
  ip TEXT, mac TEXT, hostname TEXT, vendor TEXT, os_guess TEXT,
  label TEXT DEFAULT '',             -- name chosen by the user
  trusted INTEGER DEFAULT 0,         -- 1 = user recognises this device
  online INTEGER DEFAULT 0,
  first_seen TEXT, last_seen TEXT
);
CREATE TABLE IF NOT EXISTS scans(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  network TEXT, kind TEXT, started TEXT, finished TEXT,
  hosts_found INTEGER DEFAULT 0, open_ports INTEGER DEFAULT 0,
  new_devices INTEGER DEFAULT 0, not_detected INTEGER DEFAULT 0,
  score INTEGER DEFAULT 100, grade TEXT DEFAULT '', warnings TEXT DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS ports(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
  device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE,
  port INTEGER, protocol TEXT, state TEXT, service TEXT, product TEXT, version TEXT
);
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
  device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
  rule_id TEXT, severity TEXT, title TEXT, description TEXT,
  recommendation TEXT, port INTEGER, device_name TEXT
);
CREATE TABLE IF NOT EXISTS traffic_sessions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  started TEXT, duration REAL, source TEXT,
  packets INTEGER, bytes INTEGER, summary TEXT   -- summary = JSON (metadata only, no payloads)
);
CREATE INDEX IF NOT EXISTS idx_ports_scan ON ports(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
"""


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def device_key(mac: str, ip: str) -> str:
    return mac.upper() if mac else f"ip:{ip}"


class Database:
    def __init__(self, path: Path | str = ":memory:"):
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path = str(path)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        if str(path) != ":memory:":
            self.conn.execute("PRAGMA journal_mode=WAL")      # lets the web dashboard read while a scan writes
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    @contextmanager
    def tx(self):
        try:
            yield self.conn
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    def close(self) -> None:
        self.conn.close()

    # ---- scans -----------------------------------------------------------
    def start_scan(self, network: str, kind: str) -> int:
        with self.tx() as c:
            cur = c.execute("INSERT INTO scans(network, kind, started) VALUES(?,?,?)",
                            (network, kind, now()))
            return cur.lastrowid

    def finish_scan(self, scan_id: int, **fields) -> None:
        fields["finished"] = now()
        if "warnings" in fields:
            fields["warnings"] = json.dumps(fields["warnings"])
        cols = ", ".join(f"{k}=?" for k in fields)
        with self.tx() as c:
            c.execute(f"UPDATE scans SET {cols} WHERE id=?", (*fields.values(), scan_id))

    def get_scan(self, scan_id: int) -> Optional[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()

    def latest_scan(self) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM scans WHERE finished IS NOT NULL ORDER BY id DESC LIMIT 1").fetchone()

    def scan_history(self, limit: int = 30) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM scans WHERE finished IS NOT NULL ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    # ---- devices (onboarding / offboarding, section 4.2.1) -----------------
    def reconcile_devices(self, hosts: Iterable[HostResult]) -> tuple[dict[str, int], list[int], list[int]]:
        """Compare scan results with the saved inventory.

        Returns (ip->device_id map, new_device_ids, not_detected_ids).
        Devices missing from this scan are marked offline, never deleted.
        """
        seen_ids: set[int] = set()
        new_ids: list[int] = []
        ip_map: dict[str, int] = {}
        ts = now()
        with self.tx() as c:
            for h in hosts:
                key = device_key(h.mac, h.ip)
                row = c.execute("SELECT * FROM devices WHERE key=?", (key,)).fetchone()
                if row is None and not h.mac:
                    # Same IP previously seen without a MAC?
                    row = c.execute("SELECT * FROM devices WHERE ip=? AND key LIKE 'ip:%'", (h.ip,)).fetchone()
                if row is None:
                    cur = c.execute(
                        "INSERT INTO devices(key, ip, mac, hostname, vendor, os_guess, trusted, online,"
                        " first_seen, last_seen) VALUES(?,?,?,?,?,?,?,1,?,?)",
                        (key, h.ip, h.mac.upper(), h.hostname, h.vendor, h.os_guess,
                         1 if h.is_self else 0, ts, ts))   # the machine running the tool is trusted
                    dev_id = cur.lastrowid
                    new_ids.append(dev_id)
                else:
                    dev_id = row["id"]
                    c.execute(
                        "UPDATE devices SET ip=?, mac=COALESCE(NULLIF(?,''),mac),"
                        " hostname=COALESCE(NULLIF(?,''),hostname), vendor=COALESCE(NULLIF(?,''),vendor),"
                        " os_guess=COALESCE(NULLIF(?,''),os_guess), online=1, last_seen=? WHERE id=?",
                        (h.ip, h.mac.upper(), h.hostname, h.vendor, h.os_guess, ts, dev_id))
                seen_ids.add(dev_id)
                ip_map[h.ip] = dev_id
            missing = [r["id"] for r in c.execute("SELECT id FROM devices WHERE online=1")
                       if r["id"] not in seen_ids]
            for dev_id in missing:
                c.execute("UPDATE devices SET online=0 WHERE id=?", (dev_id,))
        return ip_map, new_ids, missing

    def list_devices(self) -> list[Device]:
        rows = self.conn.execute("SELECT * FROM devices ORDER BY online DESC, ip").fetchall()
        return [self._device(r) for r in rows]

    def get_device(self, device_id: int) -> Optional[Device]:
        r = self.conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
        return self._device(r) if r else None

    @staticmethod
    def _device(r: sqlite3.Row) -> Device:
        return Device(r["id"], r["key"], r["ip"] or "", r["mac"] or "", r["hostname"] or "",
                      r["vendor"] or "", r["os_guess"] or "", r["label"] or "", bool(r["trusted"]),
                      bool(r["online"]), r["first_seen"] or "", r["last_seen"] or "")

    def rename_device(self, device_id: int, label: str) -> None:
        with self.tx() as c:
            c.execute("UPDATE devices SET label=? WHERE id=?", (label.strip(), device_id))

    def set_trusted(self, device_id: int, trusted: bool) -> None:
        with self.tx() as c:
            c.execute("UPDATE devices SET trusted=? WHERE id=?", (1 if trusted else 0, device_id))

    def trust_all_online(self) -> int:
        with self.tx() as c:
            return c.execute("UPDATE devices SET trusted=1 WHERE online=1 AND trusted=0").rowcount

    def remove_device(self, device_id: int) -> None:
        """Only ever done by explicit user action."""
        with self.tx() as c:
            c.execute("DELETE FROM devices WHERE id=?", (device_id,))

    # ---- ports & findings -------------------------------------------------
    def save_ports(self, scan_id: int, device_id: int, ports: Iterable[PortInfo]) -> None:
        with self.tx() as c:
            c.executemany(
                "INSERT INTO ports(scan_id, device_id, port, protocol, state, service, product, version)"
                " VALUES(?,?,?,?,?,?,?,?)",
                [(scan_id, device_id, p.port, p.protocol, p.state, p.service, p.product, p.version)
                 for p in ports])

    def ports_for_scan(self, scan_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT p.*, d.ip, d.label, d.hostname FROM ports p JOIN devices d ON d.id=p.device_id"
            " WHERE p.scan_id=? ORDER BY d.ip, p.port", (scan_id,)).fetchall()

    def ports_for_device(self, scan_id: int, device_id: int) -> list[PortInfo]:
        rows = self.conn.execute(
            "SELECT * FROM ports WHERE scan_id=? AND device_id=? ORDER BY port", (scan_id, device_id)).fetchall()
        return [PortInfo(r["port"], r["protocol"], r["state"], r["service"], r["product"], r["version"])
                for r in rows]

    def save_findings(self, scan_id: int, findings: Iterable[Finding]) -> None:
        with self.tx() as c:
            c.executemany(
                "INSERT INTO findings(scan_id, device_id, rule_id, severity, title, description,"
                " recommendation, port, device_name) VALUES(?,?,?,?,?,?,?,?,?)",
                [(scan_id, f.device_id, f.rule_id, f.severity, f.title, f.description,
                  f.recommendation, f.port, f.device_name) for f in findings])

    def findings_for_scan(self, scan_id: int) -> list[Finding]:
        rows = self.conn.execute("SELECT * FROM findings WHERE scan_id=?", (scan_id,)).fetchall()
        return [Finding(r["rule_id"], r["severity"], r["title"], r["description"], r["recommendation"],
                        r["device_id"], r["device_name"] or "", r["port"], r["scan_id"], r["id"]) for r in rows]

    # ---- traffic ------------------------------------------------------------
    def save_traffic(self, source: str, duration: float, packets: int, nbytes: int, summary: dict) -> int:
        with self.tx() as c:
            cur = c.execute(
                "INSERT INTO traffic_sessions(started, duration, source, packets, bytes, summary)"
                " VALUES(?,?,?,?,?,?)", (now(), duration, source, packets, nbytes, json.dumps(summary)))
            return cur.lastrowid

    def latest_traffic(self) -> Optional[dict]:
        r = self.conn.execute("SELECT * FROM traffic_sessions ORDER BY id DESC LIMIT 1").fetchone()
        if not r:
            return None
        d = dict(r)
        d["summary"] = json.loads(d["summary"])
        return d

    def purge_history(self, keep_scans: int = 20) -> None:
        """Data minimisation (section 3.5.3): drop old scans and traffic sessions."""
        with self.tx() as c:
            c.execute("DELETE FROM scans WHERE id NOT IN (SELECT id FROM scans ORDER BY id DESC LIMIT ?)",
                      (keep_scans,))
            c.execute("DELETE FROM traffic_sessions WHERE id NOT IN"
                      " (SELECT id FROM traffic_sessions ORDER BY id DESC LIMIT 10)")
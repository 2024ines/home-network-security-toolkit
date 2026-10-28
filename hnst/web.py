"""Local web dashboard (standard library only - nothing extra to install).

Runs on 127.0.0.1 so only this computer can open it. Every change request must carry a secret token
that is generated each time the server starts.
"""
from __future__ import annotations

import json
import re
import secrets
import threading
import webbrowser
from collections import Counter
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import __version__, advice, classify, config, risk
from .database import Database
from .dataview import build_data
from .models import SEVERITY_RANK
from .report import build_report
from .service import SecurityService

HTML_FILE = Path(__file__).parent / "static" / "index.html"
MAX_BODY = 65536


def _adv(f: dict) -> dict:
    """Add the plain-language explanation, steps and priority to a finding."""
    f.update(advice.advice_for(f.get("rule_id", ""), f["severity"]))
    return f


def _group(items: list[dict]) -> list[dict]:
    """One alert per kind of problem (not one per device), listing every device it was seen on."""
    groups: dict = {}
    for f in items:
        g = groups.setdefault((f.get("rule_id"), f.get("title")), dict(f, devices=[]))
        if f.get("device_name") and f["device_name"] not in g["devices"]:
            g["devices"].append(f["device_name"])
    out = []
    for g in groups.values():
        n = len(g["devices"])
        if n > 1:
            g["description"] = f"Seen from {n} devices: {', '.join(g['devices'])}. Example: {g['description']}"
        g["device"] = ", ".join(g["devices"][:4]) + (f" +{n - 4} more" if n > 4 else "")
        out.append(g)
    return out


def _ts(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------- state for the page
def build_state(db: Database, app: "WebApp") -> dict:
    scan = db.latest_scan()
    devices = db.list_devices()
    findings = db.findings_for_scan(scan["id"]) if scan else []
    by_dev: dict = {}
    for f in findings:
        by_dev.setdefault(f.device_id, []).append(f)
    my_ip = config.local_ip()
    out = []
    for d in devices:
        ports = db.ports_for_device(scan["id"], d.id) if scan else []
        open_ports = [p for p in ports if p.state == "open"]
        t, icon = classify.guess_type(d.ip, d.hostname, d.vendor, d.os_guess, [p.port for p in open_ports],
                                      is_self=(not app.demo and d.ip == my_ip))
        fl = by_dev.get(d.id, [])
        worst = max((SEVERITY_RANK[f.severity] for f in fl), default=-1)
        if not d.online:
            level = "na"
        elif worst >= SEVERITY_RANK["high"]:
            level = "risk"
        elif worst >= SEVERITY_RANK["medium"]:
            level = "review"
        else:
            level = "secure"
        out.append({
            "id": d.id, "name": d.display_name, "hostname": d.hostname, "label": d.label, "ip": d.ip,
            "mac": d.mac, "vendor": d.vendor, "os": d.os_guess, "trusted": d.trusted, "online": d.online,
            "presence": "offline" if not d.online else ("online" if d.trusted else "new"),
            "first_seen": d.first_seen, "last_seen": d.last_seen, "type": t, "icon": icon,
            "private_mac": classify.is_private_mac(d.mac), "risk": level, "open_count": len(open_ports),
            "ports": [{"port": p.port, "protocol": p.protocol, "service": p.service, "banner": p.banner}
                      for p in open_ports],
            "findings": [_adv({"rule_id": f.rule_id, "severity": f.severity, "title": f.title,
                               "description": f.description, "recommendation": f.recommendation, "port": f.port})
                         for f in fl],
        })
    online = [d for d in out if d["online"]]
    scan_info = None
    if scan:
        try:
            elapsed = round((_ts(scan["finished"]) - _ts(scan["started"])).total_seconds(), 1)
        except (TypeError, ValueError):
            elapsed = None
        scan_info = {"id": scan["id"], "network": scan["network"], "kind": scan["kind"], "started": scan["started"],
                     "finished": scan["finished"], "elapsed": elapsed, "score": scan["score"], "grade": scan["grade"],
                     "hosts": scan["hosts_found"], "open_ports": scan["open_ports"],
                     "warnings": json.loads(scan["warnings"] or "[]")}
    traffic = db.latest_traffic()
    if traffic:
        traffic["summary"]["findings"] = [_adv(x) for x in _group(traffic["summary"].get("findings", []))]
    return {
        "version": __version__, "demo": app.demo,
        "network": ("192.168.1.0/24" if app.demo else config.guess_local_network()),
        "scan": scan_info, "devices": out,
        "counts": {"total": len(out), "online": len(online), "offline": len(out) - len(online),
                   "new": sum(1 for d in online if not d["trusted"]),
                   "open_ports": sum(d["open_count"] for d in online),
                   "devices_with_ports": sum(1 for d in online if d["open_count"])},
        "findings": [_adv({"rule_id": f.rule_id, "severity": f.severity, "title": f.title,
                           "description": f.description, "recommendation": f.recommendation,
                           "device": f.device_name, "port": f.port, "device_id": f.device_id}) for f in findings],
        "severity": risk.count_by_severity(findings),
        "brands": dict(Counter(classify.brand_of(d["vendor"]) for d in online).most_common(8)),
        "types": dict(Counter(d["type"] for d in online).most_common()),
        "history": [{"finished": s["finished"], "score": s["score"], "hosts": s["hosts_found"],
                     "open_ports": s["open_ports"]} for s in reversed(db.scan_history(20))],
        "traffic": ({"started": traffic["started"], "source": traffic["source"], "summary": traffic["summary"]}
                    if traffic else None),
        "traffic_available": app.monitor is not None,
        "job": app.snapshot(),
    }


# --------------------------------------------------------------------------- app + background job
class Busy(RuntimeError):
    pass


class WebApp:
    def __init__(self, demo: bool = False, scanner=None, monitor=None, db_path=None):
        config.ensure_dirs()
        self.demo = demo
        self.db_path = str(db_path or (config.DEMO_DB_PATH if demo else config.DB_PATH))
        if scanner is None:
            if demo:
                from .demo import DemoMonitor, DemoScanner
                scanner, monitor = DemoScanner(), DemoMonitor()
            else:
                from .scanner import NmapScanner
                scanner = NmapScanner()
                from .traffic import TrafficMonitor
                monitor = TrafficMonitor()          # checks for Wireshark only when you capture, with a clear message
        self.scanner, self.monitor = scanner, monitor
        self.token = secrets.token_urlsafe(24)
        self._lock = threading.Lock()
        self._job = {"running": False, "kind": "", "message": "", "fraction": 0.0, "error": None, "stop": False}
        Database(self.db_path).close()          # creates the tables on first run

    def db(self) -> Database:
        return Database(self.db_path)           # one short-lived connection per request / job

    def snapshot(self) -> dict:
        with self._lock:
            return {k: v for k, v in self._job.items()}

    def should_stop(self) -> bool:
        with self._lock:
            return bool(self._job["stop"])

    def stop(self) -> None:
        with self._lock:
            self._job["stop"] = True

    def start(self, kind: str, fn) -> None:
        with self._lock:
            if self._job["running"]:
                raise Busy("Another task is still running. Please wait for it to finish.")
            self._job = {"running": True, "kind": kind, "message": "Starting ...", "fraction": 0.02,
                         "error": None, "stop": False}

        def progress(msg: str, frac: float) -> None:
            with self._lock:
                self._job["message"], self._job["fraction"] = msg, frac

        def worker() -> None:
            db = self.db()
            msg, err = "Done.", None
            try:
                res = fn(SecurityService(db, self.scanner, self.monitor), progress)
                if kind == "scan":
                    msg = f"Scan complete: {res.hosts_found} device(s), security score {res.score}/100."
                    if res.warnings:
                        msg += " " + res.warnings[0]
                else:
                    msg = "Traffic analysis complete."
            except Exception as exc:                      # shown to the user, never swallowed
                err = str(exc) or exc.__class__.__name__
            finally:
                db.close()
                with self._lock:
                    self._job.update(running=False, message=msg, error=err, fraction=1.0, stop=False)
        threading.Thread(target=worker, daemon=True).start()


# --------------------------------------------------------------------------- HTTP
def make_handler(app: WebApp):
    class Handler(BaseHTTPRequestHandler):
        server_version = "HNST"

        def log_message(self, *args):       # keep the terminal quiet
            pass

        # -- helpers
        def _send(self, code: int, body: bytes, ctype: str = "application/json", headers: dict | None = None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:")
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, obj) -> None:
            self._send(code, json.dumps(obj).encode("utf-8"))

        def _host_ok(self) -> bool:             # blocks DNS-rebinding style access from other websites
            return (self.headers.get("Host") or "").split(":")[0].lower() in ("127.0.0.1", "localhost")

        def _body(self) -> dict | None:
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                return None
            if n > MAX_BODY:
                return None
            try:
                data = json.loads(self.rfile.read(n) or b"{}")
            except json.JSONDecodeError:
                return None
            return data if isinstance(data, dict) else None

        # -- routes
        def do_GET(self):
            if not self._host_ok():
                return self._json(403, {"error": "Forbidden"})
            path = self.path.split("?")[0]
            if path == "/":
                html = HTML_FILE.read_text(encoding="utf-8").replace("__TOKEN__", app.token)
                return self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")
            if path == "/api/state":
                db = app.db()
                try:
                    return self._json(200, build_state(db, app))
                finally:
                    db.close()
            if path == "/api/job":
                return self._json(200, app.snapshot())
            if path == "/api/data":
                db = app.db()
                try:
                    return self._json(200, build_data(db))
                finally:
                    db.close()
            if path == "/api/check":
                from . import traffic as tr
                return self._json(200, {"checks": tr.diagnose(), "interfaces": tr.list_interfaces()})
            if path == "/api/report":
                db = app.db()
                try:
                    out = build_report(db, config.REPORT_DIR / f"report-{datetime.now():%Y%m%d-%H%M%S}.html")
                except RuntimeError as exc:
                    return self._json(400, {"error": str(exc)})
                finally:
                    db.close()
                return self._send(200, out.read_bytes(), "text/html; charset=utf-8",
                                  {"Content-Disposition": f'attachment; filename="{out.name}"'})
            self._json(404, {"error": "Not found"})

        def do_POST(self):
            if not self._host_ok():
                return self._json(403, {"error": "Forbidden"})
            if not secrets.compare_digest(self.headers.get("X-HNST-Token") or "", app.token):
                return self._json(403, {"error": "Missing or wrong security token. Refresh the page."})
            body = self._body()
            if body is None:
                return self._json(400, {"error": "Invalid request."})
            path = self.path.split("?")[0]
            try:
                if path == "/api/scan":
                    net = config.validate_network(str(body.get("network", "")))
                    if body.get("authorised") is not True:
                        return self._json(400, {"error": "Please confirm you own or are authorised to scan this network."})
                    deep = bool(body.get("deep", True))
                    app.start("scan", lambda svc, prog: svc.run_scan(net, deep, prog, app.should_stop))
                    return self._json(200, {"ok": True})
                if path == "/api/traffic":
                    if body.get("authorised") is not True:
                        return self._json(400, {"error": "Please confirm you are authorised to capture traffic here."})
                    if app.monitor is None:
                        return self._json(400, {"error": "Traffic analysis needs Wireshark (tshark) to be installed."})
                    iface = str(body.get("interface", "")).strip()[:80]
                    secs = max(5, min(300, int(body.get("seconds", 20))))
                    app.start("traffic", lambda svc, prog: svc.run_traffic(
                        iface, secs, None, lambda n: prog(f"Captured {n} packets ...", 0.5), app.should_stop))
                    return self._json(200, {"ok": True})
                if path == "/api/stop":
                    app.stop()
                    return self._json(200, {"ok": True})
                if path == "/api/trust-all":
                    db = app.db()
                    try:
                        return self._json(200, {"trusted": db.trust_all_online(), "rescored": _reassess(db)})
                    finally:
                        db.close()
                m = re.fullmatch(r"/api/device/(\d+)/(trust|rename)", path)
                if m:
                    dev_id, action = int(m.group(1)), m.group(2)
                    db = app.db()
                    try:
                        if db.get_device(dev_id) is None:
                            return self._json(404, {"error": "Device not found."})
                        if action == "trust":
                            db.set_trusted(dev_id, bool(body.get("trusted", True)))
                        else:
                            db.rename_device(dev_id, str(body.get("label", ""))[:60])
                        _reassess(db)
                        return self._json(200, {"ok": True})
                    finally:
                        db.close()
                return self._json(404, {"error": "Not found"})
            except config.NetworkNotAllowed as exc:
                return self._json(400, {"error": str(exc)})
            except Busy as exc:
                return self._json(409, {"error": str(exc)})
            except (ValueError, TypeError):
                return self._json(400, {"error": "Invalid values in the request."})
    return Handler


def _reassess(db: Database) -> bool:
    """Re-run the risk engine after the user changes trust/names, so the score stays honest."""
    scan = db.latest_scan()
    if not scan:
        return False
    devices = db.list_devices()
    ports = {d.id: db.ports_for_device(scan["id"], d.id) for d in devices if d.online}
    findings = risk.analyse(devices, ports)
    with db.tx() as c:
        c.execute("DELETE FROM findings WHERE scan_id=?", (scan["id"],))
    db.save_findings(scan["id"], findings)
    score, grade = risk.security_score(findings)
    db.finish_scan(scan["id"], score=score, grade=grade,
                   new_devices=sum(1 for d in devices if d.online and not d.trusted))
    return True


def serve(demo: bool = False, port: int = 8765, open_browser: bool = True) -> None:
    app = WebApp(demo=demo)
    httpd = None
    for p in range(port, port + 20):
        try:
            httpd = ThreadingHTTPServer(("127.0.0.1", p), make_handler(app))
            break
        except OSError:
            continue
    if httpd is None:
        raise RuntimeError("Could not find a free port. Close other programs and try again.")
    url = f"http://127.0.0.1:{httpd.server_address[1]}/"
    print(f"\n  {config.APP_NAME} {'(DEMO MODE) ' if demo else ''}is running at {url}")
    print("  Keep this window open. Press Ctrl+C to stop.\n")
    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        httpd.server_close()
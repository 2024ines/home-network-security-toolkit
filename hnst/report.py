"""Self-contained HTML security report (open in any browser, print to PDF)."""
from __future__ import annotations

import base64
import html
import io
import json
from collections import Counter
from pathlib import Path

from . import charts, config, risk
from .database import Database


def _png(fig) -> str:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=100)
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def _e(x) -> str:
    return html.escape(str(x if x is not None else ""))


def build_report(db: Database, out_path: Path | str) -> Path:
    scan = db.latest_scan()
    if not scan:
        raise RuntimeError("There is no completed scan yet. Run a scan first.")
    devices = db.list_devices()
    findings = db.findings_for_scan(scan["id"])
    ports = db.ports_for_scan(scan["id"])
    counts = risk.count_by_severity(findings)
    online_trusted = sum(1 for d in devices if d.online and d.trusted)
    new = sum(1 for d in devices if d.online and not d.trusted)
    offline = sum(1 for d in devices if not d.online)
    port_counter = Counter(f"{r['port']}/{r['service'] or '?'}" for r in ports if r["state"] == "open")

    imgs = [_png(charts.figure_score(scan["score"], scan["grade"])), _png(charts.figure_severity(counts)),
            _png(charts.figure_devices(online_trusted, new, offline)), _png(charts.figure_ports(port_counter))]
    img_html = "".join(f'<img src="{i}" alt="chart">' for i in imgs)

    dev_rows = "".join(
        f"<tr><td>{_e(d.display_name)}</td><td>{_e(d.ip)}</td><td>{_e(d.mac)}</td><td>{_e(d.vendor)}</td>"
        f"<td class='s-{d.status.split('/')[0].split()[0].lower()}'>{_e(d.status)}</td><td>{_e(d.last_seen)}</td></tr>"
        for d in devices)
    find_rows = "".join(
        f"<tr><td><span class='sev {f.severity}'>{f.severity.upper()}</span></td><td>{_e(f.device_name)}</td>"
        f"<td><b>{_e(f.title)}</b><br>{_e(f.description)}</td><td>{_e(f.recommendation)}</td></tr>"
        for f in findings) or "<tr><td colspan='4'>No findings. Nice work.</td></tr>"
    traffic = db.latest_traffic()
    traffic_html = ""
    if traffic:
        s = traffic["summary"]
        traffic_html = (f"<h2>Traffic snapshot</h2><p>{s['packets']} packets / {s['bytes']} bytes captured "
                        f"({_e(traffic['source'])}). Only packet metadata was analysed; no content was stored.</p>"
                        + "<ul>" + "".join(f"<li>{_e(f['title'])}: {_e(f['description'])}</li>"
                                           for f in s.get("findings", [])) + "</ul>")
    warn = "".join(f"<li>{_e(w)}</li>" for w in json.loads(scan["warnings"] or "[]"))

    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Home Network Security Report</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;margin:2rem auto;max-width:1000px;color:#222;padding:0 1rem}}
h1{{margin-bottom:0}} .sub{{color:#666;margin-top:.2rem}}
table{{border-collapse:collapse;width:100%;margin:.5rem 0 1.5rem;font-size:.9rem}}
th,td{{border:1px solid #ddd;padding:6px 8px;text-align:left;vertical-align:top}} th{{background:#f3f6fa}}
.charts img{{max-width:48%;margin:.5rem 0}} .sev{{padding:2px 8px;border-radius:10px;color:#fff;font-size:.75rem}}
.critical{{background:#b71c1c}}.high{{background:#e53935}}.medium{{background:#fb8c00}}
.low{{background:#c9a800}}.info{{background:#78909c}}
.s-new{{color:#e65100;font-weight:600}} .s-not{{color:#757575}} .note{{background:#fff8e1;padding:.8rem;border-left:4px solid #f9a825}}
</style></head><body>
<h1>Home Network Security Report</h1>
<p class="sub">Network {_e(scan['network'])} &middot; {_e(scan['kind'])} scan &middot; {_e(scan['finished'])} UTC</p>
<p><b>Security score: {scan['score']}/100</b> &mdash; {_e(scan['grade'])}. {len(devices)} device(s) on record,
{sum(1 for d in devices if d.online)} online.</p>
{('<div class="note"><b>Notes</b><ul>' + warn + '</ul></div>') if warn else ''}
<div class="charts">{img_html}</div>
<h2>Devices</h2><table><tr><th>Name</th><th>IP</th><th>MAC</th><th>Vendor</th><th>Status</th><th>Last seen</th></tr>{dev_rows}</table>
<h2>Findings and recommendations</h2>
<table><tr><th>Severity</th><th>Device</th><th>What we found</th><th>Suggested next step</th></tr>{find_rows}</table>
{traffic_html}
<p class="note">{_e(config.DISCLAIMER)}</p>
</body></html>"""
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(doc, encoding="utf-8")
    return out
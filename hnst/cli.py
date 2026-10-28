"""Command-line interface (also used for headless/automation use)."""
from __future__ import annotations

import argparse
import sys
from datetime import datetime

from . import __version__, config, risk
from .database import Database
from .service import SecurityService
from .report import build_report


def make_service(demo: bool, need_monitor: bool = False) -> tuple[SecurityService, Database]:
    config.ensure_dirs()
    if demo:
        from .demo import DemoMonitor, DemoScanner
        db = Database(config.DEMO_DB_PATH)
        return SecurityService(db, DemoScanner(), DemoMonitor()), db
    from .scanner import NmapScanner
    db = Database(config.DB_PATH)
    from .traffic import TrafficMonitor
    monitor = TrafficMonitor()
    return SecurityService(db, NmapScanner(), monitor), db


def _print_devices(db: Database) -> None:
    print(f"{'ID':<4}{'IP':<16}{'Name':<22}{'MAC':<19}{'Status'}")
    for d in db.list_devices():
        print(f"{d.id:<4}{d.ip:<16}{d.display_name[:20]:<22}{d.mac:<19}{d.status}")


def _print_findings(findings) -> None:
    if not findings:
        print("No findings.")
    for f in findings:
        print(f"[{f.severity.upper():8}] {f.device_name or '-':<18} {f.title}\n           -> {f.recommendation}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="hnst", description=config.APP_NAME)
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--demo", action="store_true", help="use simulated data (no real scanning)")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("gui", help="open the desktop window (Tkinter)")
    w = sub.add_parser("web", help="open the modern dashboard in your browser")
    w.add_argument("--port", type=int, default=8765)
    w.add_argument("--no-browser", action="store_true", help="do not open the browser automatically")
    s = sub.add_parser("scan", help="scan your network")
    s.add_argument("-n", "--network", help="CIDR range, e.g. 192.168.1.0/24 (default: auto-detect)")
    s.add_argument("--quick", action="store_true", help="device discovery only")
    s.add_argument("--i-am-authorised", action="store_true", required=True,
                   help="confirm you own or are authorised to scan this network")
    sub.add_parser("devices", help="list the device inventory")
    t = sub.add_parser("trust", help="mark a device as recognised")
    t.add_argument("device_id", type=int)
    t.add_argument("--all", action="store_true", help="trust every online device (baseline)")
    r = sub.add_parser("rename", help="give a device a friendly name")
    r.add_argument("device_id", type=int)
    r.add_argument("name")
    sub.add_parser("findings", help="show findings from the latest scan")
    tr = sub.add_parser("traffic", help="capture/analyse traffic (needs Wireshark/tshark and privileges)")
    tr.add_argument("-i", "--interface", default="")
    tr.add_argument("-s", "--seconds", type=int, default=20)
    tr.add_argument("--pcap", help="analyse an existing capture file instead of live traffic")
    tr.add_argument("--i-am-authorised", action="store_true", required=True)
    sub.add_parser("check", help="check that Nmap, Wireshark and permissions are set up correctly")
    rep = sub.add_parser("report", help="export an HTML report")
    rep.add_argument("-o", "--output")
    args = p.parse_args(argv)
    cmd = args.cmd or "web"

    if cmd == "gui":
        from .gui import run_gui
        run_gui(demo=args.demo)
        return 0
    if cmd == "web":
        from .web import serve
        try:
            serve(demo=args.demo, port=args.port, open_browser=not args.no_browser)
        except RuntimeError as exc:
            print("Error:", exc, "\nTip: try  python run.py --demo web", file=sys.stderr)
            return 2
        return 0

    if cmd == "check":
        from .traffic import diagnose
        for c in diagnose():
            print(f"[{'OK' if c['ok'] else '!!'}] {c['title']}: {c['detail']}")
        return 0

    try:
        if cmd == "scan":      # refuse non-private ranges before anything else happens
            from .demo import DEMO_NETWORK
            net = config.validate_network(args.network or (DEMO_NETWORK if args.demo else config.guess_local_network()))
        svc, db = make_service(args.demo, need_monitor=(cmd == "traffic"))
        if cmd == "scan":
            print(f"Scanning {net} ({'quick' if args.quick else 'full'}) ...")
            res = svc.run_scan(net, deep=not args.quick, progress=lambda m, f: print(f"  [{f:4.0%}] {m}"))
            print(f"\nDevices: {res.hosts_found} | Open ports: {res.open_ports} | Need review: {res.new_devices} | "
                  f"Not detected: {res.not_detected}")
            print(f"Security score: {res.score}/100 - {res.grade}")
            for w in res.warnings:
                print("Note:", w)
            _print_findings(res.findings)
        elif cmd == "devices":
            _print_devices(db)
        elif cmd == "trust":
            n = db.trust_all_online() if args.all else (db.set_trusted(args.device_id, True) or 1)
            print(f"Marked {n} device(s) as recognised.")
        elif cmd == "rename":
            db.rename_device(args.device_id, args.name)
            print("Renamed.")
        elif cmd == "findings":
            _print_findings(svc.current_findings())
        elif cmd == "traffic":
            summary, findings = svc.run_traffic(args.interface, args.seconds, args.pcap)
            print(f"{summary['packets']} packets, {summary['bytes']} bytes. Protocols: {summary['protocols']}")
            _print_findings(findings)
        elif cmd == "report":
            out = args.output or config.REPORT_DIR / f"report-{datetime.now():%Y%m%d-%H%M%S}.html"
            print("Report saved to", build_report(db, out))
        return 0
    except (config.NetworkNotAllowed, RuntimeError) as exc:
        print("Error:", exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
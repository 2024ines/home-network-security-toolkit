"""Orchestration layer ("Python Processing Engine" of the conceptual framework, Figure 2.5)."""
from __future__ import annotations

from typing import Callable, Optional

from . import config, risk, traffic
from .database import Database
from .models import Finding, ScanSummary
from .scanner import ScannerError


class SecurityService:
    def __init__(self, db: Database, scanner, monitor=None):
        self.db = db
        self.scanner = scanner
        self.monitor = monitor

    # ------------------------------------------------------------------ scanning
    def run_scan(self, network: str, deep: bool = True,
                 progress: Optional[Callable[[str, float], None]] = None,
                 should_stop: Optional[Callable[[], bool]] = None) -> ScanSummary:
        """Discover devices; optionally scan ports; compare with the inventory; analyse risks."""
        network = config.validate_network(network)          # raises NetworkNotAllowed
        scan_id = self.db.start_scan(network, "deep" if deep else "quick")
        warnings: list[str] = []
        try:
            hosts = self.scanner.discover(network, progress)
            _, _, missing = self.db.reconcile_devices(hosts)
            ip_to_dev = {d.ip: d for d in self.db.list_devices() if d.online}

            if deep and hosts:
                for i, h in enumerate(hosts):
                    if should_stop and should_stop():
                        warnings.append("The scan was stopped early, so results are incomplete.")
                        break
                    if progress:
                        progress(f"Checking open ports on {h.ip} ({i + 1}/{len(hosts)}) ...",
                                 0.2 + 0.7 * i / len(hosts))
                    try:
                        ports = self.scanner.scan_ports(h)
                    except ScannerError as exc:
                        warnings.append(str(exc))
                        continue
                    dev = ip_to_dev.get(h.ip)
                    if dev:
                        self.db.save_ports(scan_id, dev.id, ports)
            elif not deep:
                warnings.append("Quick scan only lists devices. Run a full scan to check open ports; "
                                "the score below does not include port checks.")
            if not hosts:
                warnings.append("No devices were found. Check the network range and that you are connected to it.")

            devices = self.db.list_devices()
            ports_by_dev = {d.id: self.db.ports_for_device(scan_id, d.id) for d in devices if d.online}
            findings = risk.analyse(devices, ports_by_dev)
            for f in findings:
                f.scan_id = scan_id
            self.db.save_findings(scan_id, findings)
            score, grade = risk.security_score(findings)
            open_ports = sum(len([p for p in v if p.state == "open"]) for v in ports_by_dev.values())
            unrecognised = sum(1 for d in devices if d.online and not d.trusted)
            self.db.finish_scan(scan_id, hosts_found=len(hosts), open_ports=open_ports,
                                new_devices=unrecognised, not_detected=len(missing),
                                score=score, grade=grade, warnings=warnings)
            if progress:
                progress("Scan complete.", 1.0)
            scan = self.db.get_scan(scan_id)
            return ScanSummary(scan_id, network, scan["kind"], scan["started"], scan["finished"],
                               len(hosts), open_ports, unrecognised, len(missing), findings, score, grade, warnings)
        except Exception:
            # Do not leave a half-finished scan looking like a success.
            self.db.finish_scan(scan_id, warnings=["Scan failed before completion."], score=0, grade="Incomplete")
            raise

    # ------------------------------------------------------------------ traffic
    def run_traffic(self, interface: str = "", seconds: int = 20, pcap: str | None = None,
                    on_packet=None, should_stop=None) -> tuple[dict, list[Finding]]:
        if self.monitor is None:
            raise RuntimeError("Traffic analysis is not available (PyShark/Wireshark not installed).")
        if pcap:
            agg = self.monitor.analyse_file(pcap)
            source = f"file:{pcap}"
        else:
            agg = self.monitor.capture_live(interface, seconds, on_packet, should_stop)
            source = f"live:{interface or 'default'}"
        if agg.packets == 0:
            raise RuntimeError("No packets were captured. Check the interface name and your capture permissions.")
        summary = agg.summary()
        known = {d.ip for d in self.db.list_devices() if d.online}
        findings = traffic.analyse_traffic(summary, known)
        summary["findings"] = [f.__dict__ for f in findings]
        self.db.save_traffic(source, float(seconds), agg.packets, agg.bytes, summary)
        return summary, findings

    # ------------------------------------------------------------------ helpers
    def current_findings(self) -> list[Finding]:
        scan = self.db.latest_scan()
        return self.db.findings_for_scan(scan["id"]) if scan else []
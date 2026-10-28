"""Nmap integration (python-nmap) for device discovery and port/service scanning."""
from __future__ import annotations

import os
import platform
import re
import subprocess
from typing import Callable, Optional

from . import config
from .models import HostResult, PortInfo

ProgressCB = Optional[Callable[[str, float], None]]   # (message, fraction 0..1)


class ScannerError(RuntimeError):
    """User-readable scanner failure (Chapter 4.4: never show half results as success)."""


def is_admin() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:   # Windows
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False


# --------------------------------------------------------------------------- parsing
def parse_discovery(nm_result: dict, own_ip: str | None = None, arp: dict[str, str] | None = None) -> list[HostResult]:
    """Convert a python-nmap result (`nm._scan_result['scan']`) into HostResult objects.

    Kept free of any nmap call so it can be unit-tested with fixtures.
    """
    arp = arp or {}
    hosts: list[HostResult] = []
    for ip, data in nm_result.items():
        if data.get("status", {}).get("state") != "up":
            continue
        addrs = data.get("addresses", {})
        mac = addrs.get("mac", "") or arp.get(ip, "")
        vendor = ""
        vend = data.get("vendor") or {}
        if mac and vend:
            vendor = next(iter(vend.values()), "")
        names = data.get("hostnames") or []
        hostname = next((n.get("name", "") for n in names if n.get("name")), "")
        os_guess = ""
        matches = data.get("osmatch") or []
        if matches:
            os_guess = matches[0].get("name", "")
        hosts.append(HostResult(ip=ip, mac=mac, hostname=hostname, vendor=vendor,
                                os_guess=os_guess, is_self=(ip == own_ip)))
    hosts.sort(key=lambda h: tuple(int(x) for x in h.ip.split(".")))
    return hosts


def parse_ports(host_data: dict) -> list[PortInfo]:
    """Extract port information for one host from a python-nmap host dict."""
    out: list[PortInfo] = []
    for proto in ("tcp", "udp"):
        for port, d in (host_data.get(proto) or {}).items():
            out.append(PortInfo(int(port), proto, d.get("state", ""), d.get("name", ""),
                                d.get("product", ""), d.get("version", "")))
    out.sort(key=lambda p: (p.protocol, p.port))
    return out


_ARP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}).*?([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})")


def read_arp_table() -> dict[str, str]:
    """Fallback MAC lookup for non-admin scans (ARP cache of the local machine)."""
    cmds = [["ip", "neigh"]] if platform.system() == "Linux" else [["arp", "-a"]]
    table: dict[str, str] = {}
    for cmd in cmds:
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        for line in out.splitlines():
            m = _ARP_RE.search(line)
            if m and not m.group(2).lower().startswith(("ff:ff", "00:00:00")):
                table[m.group(1)] = m.group(2).replace("-", ":").upper()
    return table


# --------------------------------------------------------------------------- scanner
class NmapScanner:
    """Thin wrapper around python-nmap with progress reporting and safe defaults."""

    def __init__(self):
        try:
            import nmap  # python-nmap
        except ImportError as exc:
            raise ScannerError("The 'python-nmap' package is missing. Run: pip install python-nmap") from exc
        try:
            self._nm = nmap.PortScanner()
        except nmap.PortScannerError as exc:
            raise ScannerError("Nmap is not installed or not on PATH. Install it from https://nmap.org "
                               "and restart the application.") from exc
        self._nmap = nmap

    def discover(self, network: str, progress: ProgressCB = None) -> list[HostResult]:
        network = config.validate_network(network)
        if progress:
            progress(f"Looking for devices on {network} ...", 0.05)
        try:
            self._nm.scan(hosts=network, arguments=f"-sn {config.NMAP_TIMING}")
        except self._nmap.PortScannerError as exc:
            raise ScannerError(f"Device discovery failed: {exc}") from exc
        arp = {} if is_admin() else read_arp_table()
        hosts = parse_discovery(self._nm._scan_result.get("scan", {}), config.local_ip(), arp)
        if progress:
            progress(f"Found {len(hosts)} device(s).", 0.2)
        return hosts

    def scan_ports(self, host: HostResult, os_detect: bool = False) -> list[PortInfo]:
        args = f"-sV --top-ports {config.TOP_PORTS} {config.NMAP_TIMING} --host-timeout {config.HOST_TIMEOUT}"
        if os_detect and is_admin():
            args += " -O"
        try:
            self._nm.scan(hosts=host.ip, arguments=args)
        except self._nmap.PortScannerError as exc:
            raise ScannerError(f"Port scan of {host.ip} failed: {exc}") from exc
        if host.ip not in self._nm.all_hosts():
            return []
        data = self._nm[host.ip]
        if os_detect and data.get("osmatch"):
            host.os_guess = data["osmatch"][0].get("name", "")
        return parse_ports(data)
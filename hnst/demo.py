"""Demo mode: a simulated home network so the toolkit can be shown without scanning anything real."""
from __future__ import annotations

import random

from .models import HostResult, PortInfo
from .traffic import TrafficAggregator

DEMO_NETWORK = "192.168.1.0/24"

_P = PortInfo
_DEVICES = [
    HostResult("192.168.1.1", "3C:10:00:00:00:01", "home-router", "TP-Link", "Linux 4.x"),
    HostResult("192.168.1.10", "3C:10:00:00:00:10", "ines-laptop", "Dell", "Windows 11", is_self=True),
    HostResult("192.168.1.23", "3C:10:00:00:00:23", "", "Samsung", "Android"),
    HostResult("192.168.1.31", "3C:10:00:00:00:31", "living-room-tv", "LG Electronics", ""),
    HostResult("192.168.1.45", "3C:10:00:00:00:45", "", "Hikvision", "Linux (embedded)"),
    HostResult("192.168.1.52", "3C:10:00:00:00:52", "office-printer", "HP", ""),
    HostResult("192.168.1.77", "3C:10:00:00:00:77", "", "Unknown", ""),
]
_PORTS = {
    "192.168.1.1": [_P(53, "tcp", "open", "domain", "dnsmasq", "2.80"), _P(80, "tcp", "open", "http", "lighttpd"),
                    _P(1900, "tcp", "open", "upnp", "MiniUPnP")],
    "192.168.1.10": [_P(135, "tcp", "open", "msrpc"), _P(445, "tcp", "open", "microsoft-ds")],
    "192.168.1.31": [_P(8080, "tcp", "open", "http-proxy")],
    "192.168.1.45": [_P(23, "tcp", "open", "telnet", "BusyBox telnetd"), _P(80, "tcp", "open", "http"),
                     _P(554, "tcp", "open", "rtsp")],
    "192.168.1.52": [_P(80, "tcp", "open", "http", "HP embedded web server"), _P(9100, "tcp", "open", "jetdirect")],
    "192.168.1.77": [_P(22, "tcp", "open", "ssh", "OpenSSH", "7.4"), _P(5900, "tcp", "open", "vnc")],
}


class DemoScanner:
    """Same interface as NmapScanner. Scan 1: normal network. Scan 2+: a new device appears and the phone is asleep."""

    def __init__(self):
        self.count = 0

    def discover(self, network, progress=None):
        self.count += 1
        if progress:
            progress("DEMO: simulating device discovery ...", 0.1)
        hosts = []
        for d in _DEVICES:
            if d.ip.endswith(".77") and self.count < 2:
                continue
            if d.ip.endswith(".23") and self.count >= 2:
                continue
            hosts.append(HostResult(d.ip, d.mac, d.hostname, d.vendor, d.os_guess, d.is_self))
        return hosts

    def scan_ports(self, host, os_detect=False):
        return [PortInfo(p.port, p.protocol, p.state, p.service, p.product, p.version)
                for p in _PORTS.get(host.ip, [])]


class DemoMonitor:
    def capture_live(self, interface, seconds=20, on_packet=None, should_stop=None):
        return self._synthetic()

    def analyse_file(self, path, limit=50000):
        return self._synthetic()

    @staticmethod
    def _synthetic() -> TrafficAggregator:
        rnd = random.Random(7)
        agg = TrafficAggregator()
        mix = [("TCP", 0.45), ("UDP", 0.2), ("TLS", 0.15), ("DNS", 0.1), ("HTTP", 0.05), ("TELNET", 0.02), ("ARP", 0.03)]
        protos, weights = zip(*mix)
        hosts = ["192.168.1.10", "192.168.1.31", "192.168.1.45", "192.168.1.52", "192.168.1.1", "192.168.1.88"]
        for i in range(900):
            src = rnd.choices(hosts, weights=[30, 35, 10, 5, 15, 5])[0]
            proto = rnd.choices(protos, weights=weights)[0]
            if src == "192.168.1.45" and rnd.random() < 0.3:
                proto = "TELNET"
            dst = rnd.choice(["8.8.8.8", "142.250.1.1", "192.168.1.1", "151.101.1.1", "192.168.1.10"])
            agg.add(src, dst, proto, rnd.randint(60, 1500), 1000 + i // 30)
        return agg
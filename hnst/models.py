"""Plain data objects shared by all components."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class PortInfo:
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    product: str = ""
    version: str = ""

    @property
    def banner(self) -> str:
        return " ".join(x for x in (self.product, self.version) if x).strip()


@dataclass
class HostResult:
    """What one scan learned about one device."""
    ip: str
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    os_guess: str = ""
    is_self: bool = False
    ports: list[PortInfo] = field(default_factory=list)


@dataclass
class Device:
    """A saved inventory record (SQLite)."""
    id: int
    key: str
    ip: str
    mac: str
    hostname: str
    vendor: str
    os_guess: str
    label: str
    trusted: bool
    online: bool
    first_seen: str
    last_seen: str

    @property
    def display_name(self) -> str:
        return self.label or self.hostname or self.vendor or self.ip

    @property
    def status(self) -> str:
        """Wording follows Chapter 4.2.1: never 'intruder', never auto-deleted."""
        if not self.online:
            return "Not Currently Detected"
        return "Online" if self.trusted else "New/Unrecognised"


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    description: str
    recommendation: str
    device_id: Optional[int] = None
    device_name: str = ""
    port: Optional[int] = None
    scan_id: Optional[int] = None
    id: Optional[int] = None


@dataclass
class ScanSummary:
    scan_id: int
    network: str
    kind: str
    started: str
    finished: str
    hosts_found: int
    open_ports: int
    new_devices: int
    not_detected: int
    findings: list[Finding]
    score: int
    grade: str
    warnings: list[str] = field(default_factory=list)
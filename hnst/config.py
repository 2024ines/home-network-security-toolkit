"""Central configuration and safety limits."""
from __future__ import annotations

import ipaddress
import os
import socket
from pathlib import Path

APP_NAME = "Home Network Security Toolkit"
DATA_DIR = Path(os.environ.get("HNST_HOME", Path.home() / ".hnst"))
DB_PATH = DATA_DIR / "hnst.db"
DEMO_DB_PATH = DATA_DIR / "demo.db"
REPORT_DIR = DATA_DIR / "reports"

# Safety limits (Ethical Review, section 3.5): home-sized, private networks only.
MAX_HOSTS = 1024            # refuse anything larger than a /22
TOP_PORTS = 100             # port scan depth for a standard scan
NMAP_TIMING = "-T4"
HOST_TIMEOUT = "60s"        # per-host cap so one slow device cannot stall a scan

DISCLAIMER = (
    "Only scan networks that you own or are authorised to assess. "
    "Findings are prompts for review, not proof of compromise: an open port or an "
    "unfamiliar device is often legitimate."
)


class NetworkNotAllowed(ValueError):
    """Raised when a target range is not a private home/LAN range."""


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)


def validate_network(target: str) -> str:
    """Return a normalised CIDR string, or raise NetworkNotAllowed.

    Only RFC1918 private ranges (and link-local) are accepted so the tool cannot be
    pointed at third-party systems on the internet.
    """
    try:
        net = ipaddress.ip_network(target.strip(), strict=False)
    except ValueError as exc:
        raise NetworkNotAllowed(f"'{target}' is not a valid network (example: 192.168.1.0/24).") from exc
    if net.version != 4:
        raise NetworkNotAllowed("Only IPv4 home networks are supported in this version.")
    if not (net.is_private or net.is_link_local) or net.is_loopback:
        raise NetworkNotAllowed(
            "That range is not a private home network. For safety, the toolkit only scans "
            "private ranges such as 192.168.x.x, 10.x.x.x or 172.16-31.x.x."
        )
    if net.num_addresses > MAX_HOSTS:
        raise NetworkNotAllowed(f"Range too large ({net.num_addresses} addresses). Use /22 or smaller.")
    return str(net)


def local_ip() -> str | None:
    """Best-effort local IPv4 address (no packets are actually sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def guess_local_network() -> str:
    """Guess the user's home network as a /24 around the local address."""
    ip = local_ip()
    if not ip:
        return "192.168.1.0/24"
    return str(ipaddress.ip_network(f"{ip}/24", strict=False))
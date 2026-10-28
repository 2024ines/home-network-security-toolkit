"""Traffic monitoring with Wireshark's engine (tshark). Metadata only - payloads are never read or stored.

tshark is started directly (no extra Python wrapper), which is more reliable on Windows and gives clear errors.
"""
from __future__ import annotations

import ipaddress
import os
import platform
import re
import shutil
import subprocess
import threading
import time
from collections import Counter, defaultdict

from .models import Finding

CLEARTEXT = {"TELNET": "Telnet", "FTP": "FTP", "HTTP": "HTTP", "POP": "POP3", "IMAP": "IMAP",
             "SMTP": "SMTP", "TFTP": "TFTP", "SNMP": "SNMP"}
DOMINANT_SHARE = 0.60       # one host producing >60% of packets
MIN_PACKETS_FOR_RULES = 200
FANOUT_THRESHOLD = 30       # one host contacting >30 distinct hosts in a short capture


class TrafficAggregator:
    """Collects per-packet summaries into compact statistics."""

    def __init__(self):
        self.packets = 0
        self.bytes = 0
        self.protocols: Counter = Counter()
        self.src_packets: Counter = Counter()
        self.src_bytes: Counter = Counter()
        self.dst_packets: Counter = Counter()
        self.peers: dict[str, set] = defaultdict(set)
        self.cleartext: Counter = Counter()      # (proto, src) counts
        self.timeline: Counter = Counter()       # second -> packets

    def add(self, src: str, dst: str, proto: str, length: int, ts: float = 0.0) -> None:
        proto = (proto or "UNKNOWN").upper()
        self.packets += 1
        self.bytes += int(length)
        self.protocols[proto] += 1
        if src:
            self.src_packets[src] += 1
            self.src_bytes[src] += int(length)
            if dst:
                self.peers[src].add(dst)
        if dst:
            self.dst_packets[dst] += 1
        if proto in CLEARTEXT and src:
            self.cleartext[(proto, src)] += 1
        self.timeline[int(ts)] += 1

    def summary(self, top: int = 8) -> dict:
        t0 = min(self.timeline) if self.timeline else 0
        return {
            "packets": self.packets, "bytes": self.bytes,
            "protocols": dict(self.protocols.most_common(10)),
            "top_talkers": [{"ip": ip, "packets": n, "bytes": self.src_bytes[ip],
                             "peers": len(self.peers[ip])} for ip, n in self.src_packets.most_common(top)],
            "cleartext": [{"protocol": CLEARTEXT[p], "source": s, "packets": n}
                          for (p, s), n in self.cleartext.most_common(10)],
            "timeline": [self.timeline[k] for k in sorted(self.timeline)] if self.timeline else [],
            "timeline_start": t0,
        }


def is_local(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private and not a.is_multicast
    except ValueError:
        return False


def analyse_traffic(summary: dict, known_ips: set[str], trusted_ips: set[str] | None = None) -> list[Finding]:
    """Rule-based observations on a capture. Wording stays cautious: these are indicators, not verdicts."""
    findings: list[Finding] = []
    total = summary.get("packets", 0)
    for item in summary.get("cleartext", []):
        sev = "high" if item["protocol"] in ("Telnet", "FTP") else "medium"
        findings.append(Finding(
            "TRAFFIC_CLEARTEXT", sev, f"Unencrypted {item['protocol']} traffic seen",
            f"{item['source']} sent {item['packets']} {item['protocol']} packet(s). This protocol is not encrypted, so "
            "content such as passwords could be read by others on the network.",
            "Switch the device or app to the encrypted version (HTTPS, SFTP, IMAPS...) where possible.",
            device_name=item["source"]))
    if total >= MIN_PACKETS_FOR_RULES:
        for t in summary.get("top_talkers", [])[:1]:
            share = t["packets"] / total
            if share > DOMINANT_SHARE and is_local(t["ip"]):
                findings.append(Finding(
                    "TRAFFIC_DOMINANT", "low", "One device produces most of the traffic",
                    f"{t['ip']} generated {share:.0%} of the packets in this capture. This is normal for streaming or "
                    "large downloads but can also indicate malware or a misbehaving device.",
                    "Check whether the device was streaming or updating. If not, restart it and review its apps.",
                    device_name=t["ip"]))
        for t in summary.get("top_talkers", []):
            if t["peers"] > FANOUT_THRESHOLD and is_local(t["ip"]):
                findings.append(Finding(
                    "TRAFFIC_FANOUT", "medium", "A device is contacting many other hosts",
                    f"{t['ip']} exchanged packets with {t['peers']} different addresses in a short time, which can look "
                    "like network scanning (it can also be normal for discovery protocols).",
                    "Confirm whether this is a device you expect (for example a scanner or media server).",
                    device_name=t["ip"]))
    for t in summary.get("top_talkers", []):
        if is_local(t["ip"]) and known_ips and t["ip"] not in known_ips:
            findings.append(Finding(
                "TRAFFIC_UNKNOWN_SOURCE", "medium", "Traffic from a device not in your inventory",
                f"{t['ip']} was active during the capture but is not in the device inventory.",
                "Run a new scan and review whether this device is recognised.", device_name=t["ip"]))
    return findings


# --------------------------------------------------------------------------- tshark helpers
TSHARK_MISSING = ("Wireshark (tshark) was not found. Install Wireshark from wireshark.org, keep the default options "
                  "(including Npcap), then restart this program.")
_TSHARK_PATHS = [r"C:\Program Files\Wireshark\tshark.exe", r"C:\Program Files (x86)\Wireshark\tshark.exe",
                 "/usr/bin/tshark", "/usr/local/bin/tshark", "/opt/homebrew/bin/tshark",
                 "/Applications/Wireshark.app/Contents/MacOS/tshark"]
FIELDS = ["frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "arp.src.proto_ipv4",
          "arp.dst.proto_ipv4", "frame.len", "frame.protocols"]
_PRIORITY = ["telnet", "ftp", "tftp", "snmp", "pop", "imap", "smtp", "http", "tls", "ssl", "quic", "dns", "mdns",
             "ssdp", "dhcp", "dhcpv6", "icmp", "icmpv6", "igmp", "arp", "ntp", "tcp", "udp"]
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def find_tshark() -> str | None:
    found = shutil.which("tshark")
    if found:
        return found
    return next((p for p in _TSHARK_PATHS if os.path.exists(p)), None)


def _fields_args() -> list[str]:
    args = ["-T", "fields", "-E", "separator=/t"]
    for f in FIELDS:
        args += ["-e", f]
    return args


def protocol_label(chain: str) -> str:
    """'eth:ethertype:ip:tcp:tls' -> 'TLS' (the most meaningful protocol in the packet)."""
    parts = [p for p in chain.lower().split(":") if p]
    for name in _PRIORITY:
        if name in parts:
            return name.upper()
    return (parts[-1] if parts else "unknown").upper()


def parse_line(line: str):
    """One tab-separated tshark line -> (src, dst, protocol, length, timestamp) or None."""
    f = line.rstrip("\r\n").split("\t")
    if len(f) < len(FIELDS):
        f += [""] * (len(FIELDS) - len(f))
    ts, ip_s, ip_d, v6_s, v6_d, a_s, a_d, length, chain = f[:len(FIELDS)]
    first = lambda x: x.split(",")[0].strip()          # noqa: E731  (tunnelled packets list several addresses)
    try:
        t = float(ts)
        n = int(first(length))
    except ValueError:
        return None
    return (first(ip_s) or first(v6_s) or first(a_s), first(ip_d) or first(v6_d) or first(a_d),
            protocol_label(chain), n, t)


_IFACE_RE = re.compile(r"^(\d+)\.\s+(\S+)(?:\s+\((.*)\))?\s*$")


def parse_interfaces(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        m = _IFACE_RE.match(line.strip())
        if m:
            out.append({"index": m.group(1), "device": m.group(2), "name": m.group(3) or m.group(2)})
    return out


def list_interfaces() -> list[dict]:
    exe = find_tshark()
    if not exe:
        return []
    try:
        res = subprocess.run([exe, "-D"], capture_output=True, text=True, timeout=20, creationflags=_NO_WINDOW)
    except (OSError, subprocess.SubprocessError):
        return []
    return parse_interfaces(res.stdout)


_AVOID = ("loopback", "virtual", "vmware", "vbox", "vethernet", "bluetooth", "wi-fi direct", "local area connection*",
          "docker", "isatap", "teredo", "any", "lo")
_PREFER = ("wi-fi", "wifi", "wlan", "wireless", "ethernet", "eth", "en0", "wlp", "enp")


def resolve_interface(choice: str, interfaces: list[dict]) -> dict:
    """Turn what the user typed (or nothing) into a real tshark interface."""
    if not interfaces:
        raise RuntimeError("Wireshark found no network connections to capture on. Make sure Npcap is installed "
                           "(it comes with Wireshark) and run this program as administrator.")
    c = (choice or "").strip().lower()
    if not c:
        good = [i for i in interfaces if not any(a == i["name"].lower() or a in i["name"].lower() for a in _AVOID if len(a) > 2)
                and i["name"].lower() not in ("lo", "any")]
        for want in _PREFER:
            for i in good:
                if want in i["name"].lower():
                    return i
        return (good or interfaces)[0]
    for i in interfaces:
        if c == i["index"] or c == i["name"].lower() or c == i["device"].lower():
            return i
    for i in interfaces:
        if c in i["name"].lower():
            return i
    raise RuntimeError(f"The network connection '{choice}' was not found. Choose one of: "
                       + ", ".join(i["name"] for i in interfaces))


def explain_error(stderr: str) -> str:
    s = stderr.lower()
    if "permission" in s or "access is denied" in s or "couldn't run dumpcap" in s or "don't have permission" in s:
        return ("Wireshark was not allowed to capture packets. Close VS Code, reopen it with 'Run as administrator', "
                "and make sure Npcap is installed (it comes with Wireshark).")
    if "no such device" in s or "does not exist" in s or "no interface" in s:
        return "That network connection was not found. Press 'Check my setup' and click one of the listed connections."
    if stderr.strip():
        return "Wireshark reported: " + " ".join(stderr.split())[-300:]
    return ("No packets were captured. Check that you chose the connection you are really using (Wi-Fi or Ethernet), "
            "that you are online, and that Npcap is installed.")


class TrafficMonitor:
    """Live capture or .pcap analysis through tshark. Never reads packet contents."""

    def _run(self, args: list[str], max_seconds: float, on_packet=None, should_stop=None) -> TrafficAggregator:
        exe = find_tshark()
        if not exe:
            raise RuntimeError(TSHARK_MISSING)
        cmd = [exe, "-n", "-l", *args, *_fields_args()]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                    encoding="utf-8", errors="replace", creationflags=_NO_WINDOW)
        except OSError as exc:
            raise RuntimeError(f"Could not start Wireshark: {exc}") from exc
        errors: list[str] = []
        reader = threading.Thread(target=lambda: errors.extend(proc.stderr.read().splitlines()), daemon=True)
        reader.start()
        agg = TrafficAggregator()
        deadline = time.time() + max_seconds + 15
        try:
            for line in proc.stdout:
                parsed = parse_line(line)
                if parsed:
                    agg.add(*parsed)
                    if on_packet and agg.packets % 25 == 0:
                        on_packet(agg.packets)
                if (should_stop and should_stop()) or time.time() > deadline:
                    proc.terminate()
                    break
        finally:
            try:
                proc.stdout.close()
                proc.wait(timeout=5)
            except (subprocess.TimeoutExpired, OSError, ValueError):
                proc.kill()
            reader.join(timeout=2)
        if agg.packets == 0:
            raise RuntimeError(explain_error("\n".join(errors)))
        return agg

    def capture_live(self, interface: str, seconds: int = 20, on_packet=None, should_stop=None) -> TrafficAggregator:
        if not find_tshark():
            raise RuntimeError(TSHARK_MISSING)
        iface = resolve_interface(interface, list_interfaces())
        return self._run(["-i", iface["index"], "-a", f"duration:{int(seconds)}"], seconds, on_packet, should_stop)

    def analyse_file(self, path: str, limit: int = 50000) -> TrafficAggregator:
        return self._run(["-r", path, "-c", str(limit)], 120)


# --------------------------------------------------------------------------- setup check for non-technical users
def diagnose() -> list[dict]:
    """A friendly checklist: is everything needed for scanning and traffic analysis in place?"""
    from .scanner import is_admin
    checks: list[dict] = []

    def add(ok, title, detail):
        checks.append({"ok": ok, "title": title, "detail": detail})

    admin = is_admin()
    add(admin, "Running as administrator" if admin else "Not running as administrator",
        "Good." if admin else "Needed for live traffic capture and for reading device addresses (MAC). "
        "Close VS Code, then reopen it with right-click, Run as administrator.")
    nmap = shutil.which("nmap") or next((p for p in (r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe")
                                         if os.path.exists(p)), None)
    add(bool(nmap), "Nmap (device scanner) found" if nmap else "Nmap not found",
        nmap or "Install Nmap from nmap.org, then restart this program.")
    exe = find_tshark()
    if exe:
        try:
            ver = subprocess.run([exe, "-v"], capture_output=True, text=True, timeout=15, creationflags=_NO_WINDOW)
            first = (ver.stdout or ver.stderr).splitlines()[0] if (ver.stdout or ver.stderr) else exe
        except (OSError, subprocess.SubprocessError):
            first = exe
        add(True, "Wireshark (tshark) found", first)
    else:
        add(False, "Wireshark (tshark) not found", TSHARK_MISSING)
    if platform.system() == "Windows":
        npcap = any(os.path.exists(p) for p in (r"C:\Windows\System32\Npcap", r"C:\Program Files\Npcap"))
        add(npcap, "Npcap (packet capture driver) found" if npcap else "Npcap not found",
            "Good." if npcap else "Reinstall Wireshark and tick the Npcap option, or install Npcap from npcap.com.")
    ifaces = list_interfaces() if exe else []
    if exe:
        add(bool(ifaces), f"{len(ifaces)} network connection(s) available" if ifaces else "No network connections available to capture",
            ", ".join(i["name"] for i in ifaces) if ifaces else "Usually means Npcap is missing or you are not an administrator.")
    return checks
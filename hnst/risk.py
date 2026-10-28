"""Risk engine: turns technical results into plain-language findings and a score.

Wording is deliberately cautious (Chapter 4.3 / 4.6): an open port or an
unfamiliar device is something to *review*, not proof of an attack.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .models import SEVERITY_RANK, Device, Finding, PortInfo


@dataclass(frozen=True)
class PortRule:
    rule_id: str
    severity: str
    title: str
    why: str
    fix: str


PORT_RULES: dict[int, PortRule] = {
    21: PortRule("PORT_FTP", "high", "File Transfer (FTP) is reachable",
                 "FTP sends usernames, passwords and files without encryption, so anyone on the network could read them.",
                 "If you do not use FTP, turn it off on this device. Otherwise switch to SFTP and use a strong password."),
    23: PortRule("PORT_TELNET", "critical", "Telnet remote login is reachable",
                 "Telnet is an old remote-login service that sends everything, including passwords, in clear text. "
                 "It is a common target for IoT malware.",
                 "Disable Telnet in the device settings and use SSH instead. Change any default password and update the firmware."),
    22: PortRule("PORT_SSH", "low", "SSH remote login is reachable",
                 "SSH is encrypted and normally safe, but weak passwords make it a target for guessing attacks.",
                 "Make sure you actually use SSH. If so, use key-based login or a long unique password."),
    25: PortRule("PORT_SMTP", "medium", "A mail server port (SMTP) is open",
                 "Home devices rarely need to run a mail server; an open mail port can be abused to send spam.",
                 "Disable the mail service if you did not set it up deliberately."),
    53: PortRule("PORT_DNS", "info", "A DNS service is running",
                 "Routers normally answer DNS queries for your home. On other devices it is unusual.",
                 "No action needed on a router. On other devices, confirm you set it up on purpose."),
    69: PortRule("PORT_TFTP", "medium", "TFTP is reachable",
                 "TFTP has no login or encryption and is often left on by mistake.",
                 "Turn off TFTP unless you are deliberately transferring firmware."),
    80: PortRule("PORT_HTTP", "low", "A web page (HTTP) is served without encryption",
                 "Admin pages on plain HTTP expose passwords to anyone who can see the traffic on your Wi-Fi.",
                 "Use the HTTPS version of the admin page if available and change the default admin password."),
    110: PortRule("PORT_POP3", "medium", "Unencrypted mail retrieval (POP3) is open",
                  "POP3 can send mail passwords in clear text.", "Disable it or use the encrypted version."),
    135: PortRule("PORT_RPC", "medium", "Windows RPC port is reachable",
                  "Windows network services should not be reachable by every device on the network.",
                  "Keep Windows updated and make sure the Windows Firewall is on."),
    139: PortRule("PORT_NETBIOS", "medium", "Windows file-sharing (NetBIOS) is reachable",
                  "Old Windows sharing can leak computer names and shared folders.",
                  "Turn off file sharing you do not need and keep the firewall on."),
    161: PortRule("PORT_SNMP", "medium", "SNMP management service is reachable",
                  "SNMP with the default community name ('public') can reveal device details.",
                  "Disable SNMP or change the community string if you do not use it."),
    445: PortRule("PORT_SMB", "medium", "Windows file sharing (SMB) is reachable",
                  "SMB has been used by worms such as WannaCry when systems were out of date.",
                  "Install Windows updates, disable SMBv1 and share only the folders you need."),
    554: PortRule("PORT_RTSP", "medium", "Video streaming (RTSP) is reachable",
                  "Cameras that stream over RTSP sometimes have no password or a default one.",
                  "Set a strong camera password, update its firmware and do not expose it to the internet."),
    1900: PortRule("PORT_UPNP", "medium", "UPnP is active",
                   "UPnP lets devices open ports on the router automatically, which can expose them to the internet.",
                   "Disable UPnP in the router unless a device really needs it."),
    3306: PortRule("PORT_MYSQL", "high", "A database (MySQL) is reachable on the network",
                   "Databases should only be reachable from the device that needs them.",
                   "Bind the database to localhost or block the port with the firewall."),
    3389: PortRule("PORT_RDP", "high", "Remote Desktop (RDP) is reachable",
                   "RDP is a frequent target for password-guessing and ransomware.",
                   "Turn off Remote Desktop if you do not use it; otherwise require a strong password and updates."),
    5555: PortRule("PORT_ADB", "high", "Android debug bridge (ADB) is reachable",
                   "ADB over the network can allow control of a device without a password.",
                   "Disable network debugging in the device's developer options."),
    5900: PortRule("PORT_VNC", "high", "Remote screen sharing (VNC) is reachable",
                   "VNC is often protected by weak or no passwords.",
                   "Turn it off or set a strong password and limit access."),
    8080: PortRule("PORT_HTTP_ALT", "low", "An alternative web page (port 8080) is served",
                   "Alternative web ports are commonly used by admin pages of cameras and printers.",
                   "Check what is served here and set a strong admin password."),
    37777: PortRule("PORT_DVR", "medium", "Camera/DVR service is reachable",
                    "DVR and camera ports are targeted by botnets when passwords are not changed.",
                    "Change the default password and update the firmware."),
}

# Points deducted from a 100-point score per finding.
SEVERITY_PENALTY = {"info": 0, "low": 2, "medium": 6, "high": 12, "critical": 20}
MANY_PORTS_THRESHOLD = 10


def analyse(devices: Iterable[Device], ports_by_device: dict[int, list[PortInfo]]) -> list[Finding]:
    """Create findings for the devices that are currently online."""
    findings: list[Finding] = []
    for dev in devices:
        if not dev.online:
            continue
        name = dev.display_name
        if not dev.trusted:
            findings.append(Finding(
                "NEW_DEVICE", "medium", "New or unrecognised device",
                f"{name} ({dev.ip}) has joined the network and has not been marked as recognised. "
                "It may belong to you, a family member or a guest.",
                "Check whether this device is yours or belongs to someone you allowed. If it is familiar, mark it as "
                "recognised. If not, change your Wi-Fi password and review the router's connected-devices list.",
                dev.id, name))
        open_ports = [p for p in ports_by_device.get(dev.id, []) if p.state == "open"]
        for p in open_ports:
            rule = PORT_RULES.get(p.port)
            if not rule:
                continue
            extra = f" Detected as: {p.service} {p.banner}".rstrip() + "." if p.service or p.banner else ""
            findings.append(Finding(
                rule.rule_id, rule.severity, rule.title,
                f"{name} ({dev.ip}) has port {p.port}/{p.protocol} open. {rule.why}{extra} "
                "An open port alone does not prove the device is vulnerable.",
                rule.fix, dev.id, name, p.port))
        if len(open_ports) >= MANY_PORTS_THRESHOLD:
            findings.append(Finding(
                "MANY_PORTS", "medium", "Many open ports on one device",
                f"{name} ({dev.ip}) has {len(open_ports)} open ports, which enlarges its attack surface.",
                "Turn off services you do not use and keep the device's software up to date.",
                dev.id, name))
    findings.sort(key=lambda f: (-SEVERITY_RANK[f.severity], f.device_name, f.port or 0))
    return findings


def security_score(findings: Iterable[Finding]) -> tuple[int, str]:
    """0-100 score and a plain label. Repeated findings of the same rule count with diminishing weight."""
    seen: dict[str, int] = {}
    penalty = 0.0
    for f in findings:
        n = seen.get(f.rule_id, 0)
        seen[f.rule_id] = n + 1
        penalty += SEVERITY_PENALTY[f.severity] * (1.0 if n == 0 else 0.5)
    score = max(0, min(100, round(100 - penalty)))
    return score, grade(score)


def grade(score: int) -> str:
    if score >= 90:
        return "Good"
    if score >= 70:
        return "Fair - a few things to review"
    if score >= 50:
        return "Needs attention"
    return "At risk - act soon"


def count_by_severity(findings: Iterable[Finding]) -> dict[str, int]:
    out = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        out[f.severity] += 1
    return out
"""Plain-language explanations and step-by-step fixes for non-technical users."""
from __future__ import annotations

PRIORITY = {
    "critical": "Fix today", "high": "Fix today", "medium": "Fix this week",
    "low": "When you have time", "info": "Nothing to do",
}

_ROUTER = "Log in to your router (the address and password are usually on a sticker on the router, often 192.168.1.1)."

ADVICE: dict[str, dict] = {
    "NEW_DEVICE": {
        "simple": "A device is on your Wi-Fi that you have not told the toolkit about yet. It is often a guest's phone or a new gadget, but it is worth a quick check.",
        "steps": ["Open the Devices page and click Details on the device to see its brand and type.",
                  "Ask your family or guests, and look at your own phones, TVs and game consoles.",
                  "If you know it, press 'Mark as recognised' and give it a friendly name.",
                  "If nobody knows it, change your Wi-Fi password in the router, reconnect your own devices, then scan again."],
        "time": "5 minutes", "skill": "Easy: you can do this yourself"},
    "MANY_PORTS": {
        "simple": "This device is running many network services at once. Each one is another possible way in, so fewer is safer.",
        "steps": ["Open the device's settings and look for 'services', 'sharing' or 'remote access'.",
                  "Turn off anything you do not use.", "Install the latest updates for the device.", "Scan again to see if the number drops."],
        "time": "15 minutes", "skill": "Medium: needs the device's settings"},
    "PORT_TELNET": {
        "simple": "This device allows an old, unsafe kind of remote login. Passwords sent this way can be read by anyone nearby, and hackers actively look for it on cameras and routers.",
        "steps": ["Open the device's app or web page and sign in as the owner.", "Find Settings, then Network or Services, and switch Telnet off.",
                  "Change the device password to a long, unique one.", "Install the latest firmware (software update) from the maker.",
                  "If you cannot switch it off, ask the maker for help or replace the device."],
        "time": "15 minutes", "skill": "Medium: needs the device's settings"},
    "PORT_FTP": {
        "simple": "This device offers file transfer that does not hide passwords or files from people on your network.",
        "steps": ["If you never share files from this device, switch the FTP or file-transfer service off in its settings.",
                  "If you need it, use the secure version (SFTP) and a strong password.", "Scan again to confirm."],
        "time": "10 minutes", "skill": "Medium: needs the device's settings"},
    "PORT_SSH": {
        "simple": "This device allows secure remote login. That is normal for computers and some gadgets, but guessable passwords make it a target.",
        "steps": ["If you do not use remote login, switch it off in the device settings.", "If you do, use a long, unique password."],
        "time": "5 minutes", "skill": "Easy: you can do this yourself"},
    "PORT_SMTP": {
        "simple": "This device is set up to send email for others. Home devices rarely need this, and criminals can misuse it to send spam.",
        "steps": ["Open the device settings and switch off any mail server or 'SMTP' service.", "Scan again to confirm."],
        "time": "10 minutes", "skill": "Medium: needs the device's settings"},
    "PORT_DNS": {
        "simple": "This device answers internet address lookups. That is normal for your router.",
        "steps": ["If this is your router, nothing to do.", "If it is something else, check you meant to set it up."],
        "time": "None", "skill": "Easy: you can do this yourself"},
    "PORT_TFTP": {
        "simple": "A very simple file service with no password is switched on. It is often left on by mistake.",
        "steps": ["Switch TFTP off in the device settings unless you are updating its software on purpose.", "Scan again to confirm."],
        "time": "10 minutes", "skill": "Medium: needs the device's settings"},
    "PORT_HTTP": {
        "simple": "This device has a settings web page that is not protected by encryption. Anyone on your Wi-Fi could see the password you type there.",
        "steps": ["Change the default admin password (often 'admin') to a long, unique one.", "Use the secure (https) address of the page if the device offers one.",
                  "Do not log in to it from public Wi-Fi."],
        "time": "10 minutes", "skill": "Easy: you can do this yourself"},
    "PORT_POP3": {
        "simple": "An old way of collecting email that can send your mail password without hiding it.",
        "steps": ["Switch it off, or change the app to use the secure version (POP3S or IMAPS).", "Scan again to confirm."],
        "time": "10 minutes", "skill": "Medium: needs the device's settings"},
    "PORT_RPC": {
        "simple": "A Windows service that helps programs talk to each other is visible on your network. It is normal on Windows PCs, but should be behind a firewall and kept up to date.",
        "steps": ["Open Windows Update and install all updates.", "Open Windows Security, then Firewall & network protection, and make sure the firewall is On.", "Scan again."],
        "time": "15 minutes", "skill": "Easy: you can do this yourself"},
    "PORT_NETBIOS": {
        "simple": "Old-style Windows file sharing is on. It can reveal your computer name and shared folders to others on the network.",
        "steps": ["Open Control Panel, then Network and Sharing Center, then Advanced sharing settings.", "Turn off 'File and printer sharing' unless you need it.",
                  "Make sure Windows Firewall is On."],
        "time": "10 minutes", "skill": "Easy: you can do this yourself"},
    "PORT_SNMP": {
        "simple": "A device-management service is on. With its default settings it can reveal details about the device to anyone on your network.",
        "steps": ["Switch SNMP off in the device settings if you do not use it.", "If you need it, change the default community name 'public'."],
        "time": "10 minutes", "skill": "Medium: needs the device's settings"},
    "PORT_SMB": {
        "simple": "Windows file sharing is visible on your network. Out-of-date computers were hit by the WannaCry ransomware this way.",
        "steps": ["Open Windows Update and install all updates.", "Share only the folders you really need, and remove the rest.",
                  "Keep Windows Firewall switched On.", "Scan again."],
        "time": "15 minutes", "skill": "Easy: you can do this yourself"},
    "PORT_RTSP": {
        "simple": "This camera streams video on your network. Cameras with weak or default passwords can be watched by strangers.",
        "steps": ["Open the camera's app and set a long, unique password.", "Install the latest camera firmware (software update).",
                  "Make sure the camera is not opened to the internet in your router settings."],
        "time": "15 minutes", "skill": "Medium: needs the device's settings"},
    "PORT_UPNP": {
        "simple": "UPnP lets gadgets open doors in your router on their own. Convenient, but a bad gadget can open a door to the internet without you knowing.",
        "steps": [_ROUTER, "Look for 'UPnP' (often under Advanced or NAT settings).", "Switch it off and save.",
                  "If a game or device stops working, you can switch it back on."],
        "time": "10 minutes", "skill": "Medium: needs your router login"},
    "PORT_MYSQL": {
        "simple": "A database is reachable from other devices. Databases should normally only be used by the computer they run on.",
        "steps": ["If you did not set up a database, uninstall or stop the service.", "If you did, set it to accept local connections only, or block it in the firewall."],
        "time": "20 minutes", "skill": "Hard: ask a tech-savvy friend"},
    "PORT_RDP": {
        "simple": "Remote Desktop is on, which lets someone control this computer from far away. Criminals try to guess passwords on it all the time.",
        "steps": ["On the computer open Settings, then System, then Remote Desktop.", "Switch Remote Desktop Off if you do not use it.",
                  "Make sure the computer has a strong password and all Windows updates."],
        "time": "5 minutes", "skill": "Easy: you can do this yourself"},
    "PORT_ADB": {
        "simple": "An Android device allows 'debugging' over the network, which can let someone control it without a password.",
        "steps": ["On the device open Settings, then Developer options.", "Switch off 'Wireless debugging' or 'ADB over network'.", "Restart the device and scan again."],
        "time": "5 minutes", "skill": "Easy: you can do this yourself"},
    "PORT_VNC": {
        "simple": "Screen sharing is on. If its password is weak or missing, someone could see and control this device.",
        "steps": ["Close or uninstall the VNC / screen-sharing program if you do not use it.", "If you use it, set a long, unique password."],
        "time": "10 minutes", "skill": "Medium: needs the device's settings"},
    "PORT_HTTP_ALT": {
        "simple": "This device has an extra settings web page (printers, cameras and TVs often do).",
        "steps": ["Open it in a browser (type the IP address, a colon and the port number).", "Set a strong admin password if it asks for one.", "Update the device software."],
        "time": "10 minutes", "skill": "Easy: you can do this yourself"},
    "PORT_DVR": {
        "simple": "A camera or video recorder service is visible. These are a favourite target of criminals when the password was never changed.",
        "steps": ["Change the default password in the camera or recorder settings.", "Install the latest firmware.", "Do not open it to the internet."],
        "time": "15 minutes", "skill": "Medium: needs the device's settings"},
    "TRAFFIC_CLEARTEXT": {
        "simple": "A device sent information in a form anyone on your Wi-Fi could read, like a postcard instead of a sealed letter.",
        "steps": ["Find the device with the address shown in the message (see the Devices page).",
                  "Use the secure version of the app or website (look for https and a padlock).", "Update the app or device software.",
                  "Avoid typing passwords on that device until it is fixed."],
        "time": "10 minutes", "skill": "Easy: you can do this yourself"},
    "TRAFFIC_DOMINANT": {
        "simple": "One device is using most of your network. Often that is just a video or a large download.",
        "steps": ["Ask whether someone was streaming, gaming or downloading.", "If nobody was, restart that device.",
                  "Run a virus scan on it, and scan your network again."],
        "time": "10 minutes", "skill": "Easy: you can do this yourself"},
    "TRAFFIC_FANOUT": {
        "simple": "One device contacted lots of other devices very quickly, which can look like searching the network. Smart TVs and speakers do this too, so it is often harmless.",
        "steps": ["Check on the Devices page what that device is.", "If it is a TV, speaker or scanner, no action is needed.", "If you do not recognise it, change your Wi-Fi password and scan again."],
        "time": "5 minutes", "skill": "Easy: you can do this yourself"},
    "TRAFFIC_UNKNOWN_SOURCE": {
        "simple": "A device was active on your network that is not in your device list.",
        "steps": ["Run a Full scan so it is added to the list.", "Open Devices, check what it is, and mark it recognised if it is yours."],
        "time": "5 minutes", "skill": "Easy: you can do this yourself"},
}

_GENERIC = {
    "simple": "The toolkit found something that is worth a quick look.",
    "steps": ["Read the technical details below.", "If you do not use or recognise this, switch it off in the device settings.", "Run a Full scan again to confirm."],
    "time": "10 minutes", "skill": "Medium: needs the device's settings",
}


def advice_for(rule_id: str, severity: str) -> dict:
    """Return plain-language help for a finding (always safe to call)."""
    base = ADVICE.get(rule_id, _GENERIC)
    return {"simple": base["simple"], "steps": list(base["steps"]), "time": base["time"], "skill": base["skill"],
            "priority": PRIORITY.get(severity, "When you have time")}
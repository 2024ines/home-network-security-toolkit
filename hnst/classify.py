"""Best-guess device type from vendor, name, OS and open ports (used for icons and the 'by type' chart)."""
from __future__ import annotations

TYPES = {
    "Router": "📡", "Computer": "💻", "Phone / Tablet": "📱", "TV / Media": "📺", "Camera": "📹",
    "Printer": "🖨️", "Game console": "🎮", "Smart device": "💡", "Unknown": "❔",
}

_PRINTER = ("printer", "laserjet", "officejet", "epson", "canon", "brother", "xerox", "lexmark", "ricoh", "konica")
_CAMERA = ("hikvision", "dahua", "reolink", "ipcam", "camera", "amcrest", "wyze", "foscam", "tapo", "ezviz")
_GAME = ("nintendo", "xbox", "playstation", "sony interactive")
_TV = ("roku", "vizio", "hisense", "tcl", "chromecast", "firetv", "appletv", "smarttv", "bravia", "webos",
       "tizen", "lg electronics", "lg-tv", "android tv")
_ROUTER_VENDOR = ("tp-link", "netgear", "mikrotik", "ubiquiti", "zte", "d-link", "linksys", "cisco", "arris",
                  "technicolor", "sagemcom", "tenda", "huawei technologies")
_COMPUTER = ("dell", "lenovo", "asustek", "acer", "msi", "intel", "microsoft", "gigabyte", "hewlett", "desktop-",
             "laptop", "-pc", "macbook", "imac", "thinkpad", "windows", "linux", "mac os")
_SMART = ("espressif", "tuya", "shelly", "raspberry", "amazon", "echo", "nest", "sonos", "philips", "hue",
          "bulb", "plug", "smart", "iot", "ring")
_PHONE = ("iphone", "ipad", "android", "galaxy", "pixel", "oneplus", "xiaomi", "redmi", "oppo", "vivo", "tecno",
          "infinix", "realme", "motorola", "nokia", "samsung", "apple", "huawei")


def is_private_mac(mac: str) -> bool:
    """Phones and laptops often use a random 'private' Wi-Fi address; vendor lookup then fails."""
    try:
        return bool(int(mac[:2], 16) & 2)
    except (ValueError, TypeError):
        return False


def _has(text: str, words) -> bool:
    return any(w in text for w in words)


def guess_type(ip: str = "", hostname: str = "", vendor: str = "", os_guess: str = "",
               ports=(), is_self: bool = False) -> tuple[str, str]:
    h, v, o, ps = hostname.lower(), vendor.lower(), os_guess.lower(), set(ports)
    ident = f"{h} {v} {o}"
    last = ip.rsplit(".", 1)[-1] if ip else ""
    if is_self:
        t = "Computer"
    elif ps & {9100, 631, 515} or _has(ident, _PRINTER):
        t = "Printer"
    elif ps & {554, 37777} or _has(ident, _CAMERA):
        t = "Camera"
    elif _has(ident, _GAME):
        t = "Game console"
    elif _has(ident, _TV) and not _has(h, ("iphone", "galaxy-s", "pixel")):
        t = "TV / Media"
    elif _has(h, ("router", "gateway")) or _has(v, _ROUTER_VENDOR) or (last in ("1", "254") and ps & {53, 1900}):
        t = "Router"
    elif _has(ident, _COMPUTER) or ps & {445, 135, 139, 3389}:
        t = "Computer"
    elif _has(ident, _SMART):
        t = "Smart device"
    elif _has(ident, _PHONE):
        t = "Phone / Tablet"
    else:
        t = "Unknown"
    return t, TYPES[t]


def brand_of(vendor: str) -> str:
    v = (vendor or "").strip()
    if not v or v.lower() == "unknown":
        return "Unrecognised"
    return v.split()[0].rstrip(",")
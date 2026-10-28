"""Visual theme: one place to change colours, fonts and button looks."""
from __future__ import annotations

from tkinter import ttk

# Palette ----------------------------------------------------------------
NAVY = "#0f172a"        # header, table headings
NAVY_SOFT = "#1e293b"
BG = "#f1f5f9"          # window background
CARD = "#ffffff"
TEXT = "#0f172a"
MUTED = "#64748b"
ACCENT = "#0d9488"      # teal: main buttons
ACCENT_HOVER = "#0f766e"
ACCENT_LIGHT = "#ccfbf1"
DANGER = "#dc2626"
DANGER_HOVER = "#b91c1c"
WARN_BG = "#fef3c7"
WARN_FG = "#92400e"

FONT = "Segoe UI"


def apply(root) -> None:
    """Call once, right after creating the Tk window."""
    root.configure(bg=BG)
    s = ttk.Style(root)
    try:
        s.theme_use("clam")        # 'clam' lets us colour buttons on every OS
    except Exception:
        pass

    s.configure(".", font=(FONT, 10), background=BG, foreground=TEXT)
    s.configure("TFrame", background=BG)
    s.configure("TLabel", background=BG, foreground=TEXT)
    s.configure("TCheckbutton", background=BG, foreground=TEXT)
    s.map("TCheckbutton", background=[("active", BG)])
    s.configure("TEntry", padding=6, fieldbackground=CARD)
    s.configure("TCombobox", padding=5)

    # Header banner
    s.configure("Header.TFrame", background=NAVY)
    s.configure("Header.TLabel", background=NAVY, foreground="white", font=(FONT, 18, "bold"))
    s.configure("HeaderSub.TLabel", background=NAVY, foreground="#94a3b8", font=(FONT, 10))
    s.configure("Pill.TLabel", background=ACCENT, foreground="white", font=(FONT, 9, "bold"), padding=(10, 3))
    s.configure("PillDemo.TLabel", background="#f59e0b", foreground=NAVY, font=(FONT, 9, "bold"), padding=(10, 3))

    # Cards and text styles
    s.configure("Card.TFrame", background=CARD, relief="flat")
    s.configure("Card.TLabel", background=CARD, foreground=TEXT)
    s.configure("StatNum.TLabel", background=CARD, foreground=NAVY, font=(FONT, 26, "bold"))
    s.configure("StatLbl.TLabel", background=CARD, foreground=MUTED, font=(FONT, 9))
    s.configure("Title.TLabel", background=BG, foreground=NAVY, font=(FONT, 12, "bold"))
    s.configure("Muted.TLabel", background=BG, foreground=MUTED)
    s.configure("Status.TFrame", background=NAVY_SOFT)
    s.configure("Status.TLabel", background=NAVY_SOFT, foreground="#cbd5e1", font=(FONT, 9))

    # Buttons
    base = dict(font=(FONT, 10, "bold"), padding=(14, 8), borderwidth=0, focusthickness=0, relief="flat")
    s.configure("TButton", background="#e2e8f0", foreground=NAVY, **base)
    s.map("TButton", background=[("active", "#cbd5e1"), ("disabled", "#e5e7eb")],
          foreground=[("disabled", "#94a3b8")])
    s.configure("Accent.TButton", background=ACCENT, foreground="white", **base)
    s.map("Accent.TButton", background=[("active", ACCENT_HOVER), ("disabled", "#99d5cf")],
          foreground=[("disabled", "#e6fffb")])
    s.configure("Danger.TButton", background=DANGER, foreground="white", **base)
    s.map("Danger.TButton", background=[("active", DANGER_HOVER), ("disabled", "#fca5a5")])
    s.configure("Big.TButton", **base)

    # Tables
    s.configure("Treeview", rowheight=30, background=CARD, fieldbackground=CARD, foreground=TEXT,
                borderwidth=0, font=(FONT, 10))
    s.map("Treeview", background=[("selected", ACCENT_LIGHT)], foreground=[("selected", NAVY)])
    s.configure("Treeview.Heading", background=NAVY, foreground="white", font=(FONT, 10, "bold"),
                padding=(8, 7), relief="flat")
    s.map("Treeview.Heading", background=[("active", NAVY_SOFT)])

    # Tabs
    s.configure("TNotebook", background=BG, borderwidth=0, tabmargins=(0, 4, 0, 0))
    s.configure("TNotebook.Tab", background="#e2e8f0", foreground=MUTED, padding=(20, 9), font=(FONT, 10, "bold"))
    s.map("TNotebook.Tab", background=[("selected", CARD)], foreground=[("selected", ACCENT)])

    # Progress bar
    s.configure("Horizontal.TProgressbar", troughcolor="#334155", background="#2dd4bf", thickness=10, borderwidth=0)
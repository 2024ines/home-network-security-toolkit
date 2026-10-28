"""Tkinter dashboard (Chapter 4.6): scan, devices, findings, traffic, history."""
from __future__ import annotations

import queue
import threading
import tkinter as tk
import webbrowser
from collections import Counter
from datetime import datetime
from tkinter import filedialog, messagebox, simpledialog, ttk

import matplotlib
matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg  # noqa: E402

from . import charts, config, risk, theme
from .cli import make_service
from .demo import DEMO_NETWORK
from .models import SEVERITIES, SEVERITY_RANK
from .report import build_report
from .scanner import ScannerError

SEV_BG = {"critical": "#ffcdd2", "high": "#ffe0e0", "medium": "#ffe9cc", "low": "#fff7c2", "info": "#eceff1"}
FRIENDLY = {"Online": "Recognised", "New/Unrecognised": "Needs review", "Not Currently Detected": "Not detected now"}


class App(tk.Tk):
    def __init__(self, demo: bool = False):
        super().__init__()
        self.title(config.APP_NAME)
        self.geometry("1180x760")
        self.minsize(980, 640)
        self.demo = demo
        self.svc = self.db = None
        self._init_service()
        self.q: queue.Queue = queue.Queue()
        self.busy = False
        self.stop_flag = threading.Event()
        self._canvases: dict[str, FigureCanvasTkAgg] = {}
        self._build_ui()
        self.refresh_all()
        self.after(100, self._poll)

    # ------------------------------------------------------------------ setup
    def _init_service(self):
        try:
            self.svc, self.db = make_service(self.demo)
        except (ScannerError, RuntimeError) as exc:
            if messagebox.askyesno("Scanner not available",
                                   f"{exc}\n\nOpen in demo mode with simulated data instead?"):
                self.demo = True
                self.svc, self.db = make_service(True)
            else:
                raise SystemExit(1)

    def _build_ui(self):
        theme.apply(self)

        header = ttk.Frame(self, style="Header.TFrame", padding=(20, 14))
        header.pack(fill="x")
        titles = ttk.Frame(header, style="Header.TFrame")
        titles.pack(side="left")
        ttk.Label(titles, text="Home Network Security Toolkit", style="Header.TLabel").pack(anchor="w")
        ttk.Label(titles, text="See what is on your network. Fix what matters.", style="HeaderSub.TLabel").pack(anchor="w")
        if self.demo:
            ttk.Label(header, text="DEMO MODE - simulated data", style="PillDemo.TLabel").pack(side="right")
        else:
            ttk.Label(header, text="LIVE", style="Pill.TLabel").pack(side="right")

        bar = ttk.Frame(self, padding=(14, 12))
        bar.pack(fill="x")
        ttk.Label(bar, text="Network:").pack(side="left")
        self.net_var = tk.StringVar(value=DEMO_NETWORK if self.demo else config.guess_local_network())
        ttk.Entry(bar, textvariable=self.net_var, width=18).pack(side="left", padx=(4, 10))
        self.auth_var = tk.BooleanVar(value=self.demo)
        ttk.Checkbutton(bar, text="I own / am authorised to scan this network", variable=self.auth_var).pack(side="left")
        self.btns: list[ttk.Button] = []
        for text, cmd in (("Full scan", lambda: self.start_scan(True)), ("Quick scan", lambda: self.start_scan(False)),
                          ("Export report", self.export_report)):
            b = ttk.Button(bar, text=text, command=cmd,
                           style="Accent.TButton" if text == "Full scan" else "TButton")
            b.pack(side="right", padx=3)
            self.btns.append(b)
        self.stop_btn = ttk.Button(bar, text="Stop", command=self.stop_flag.set, state="disabled", style="Danger.TButton")
        self.stop_btn.pack(side="right", padx=3)

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=14, pady=(0, 8))
        self.tab_dash, self.tab_dev, self.tab_find, self.tab_traffic, self.tab_hist = (ttk.Frame(self.nb) for _ in range(5))
        for t, name in ((self.tab_dash, "Dashboard"), (self.tab_dev, "Devices"), (self.tab_find, "Findings"),
                        (self.tab_traffic, "Traffic"), (self.tab_hist, "History")):
            self.nb.add(t, text=name)
        self._build_dashboard()
        self._build_devices()
        self._build_findings()
        self._build_traffic()
        self._build_history()

        status = ttk.Frame(self, style="Status.TFrame")
        status.pack(fill="x", side="bottom")
        self.status_var = tk.StringVar(value="Ready. " + config.DISCLAIMER)
        ttk.Label(status, textvariable=self.status_var, wraplength=900, style="Status.TLabel").pack(side="left", padx=12, pady=6)
        self.progress = ttk.Progressbar(status, length=160, mode="determinate")
        self.progress.pack(side="right", padx=12)

    # ------------------------------------------------------------------ dashboard
    def _build_dashboard(self):
        top = ttk.Frame(self.tab_dash, padding=8)
        top.pack(fill="x")
        self.summary_var = tk.StringVar(value="No scan yet. Tick the authorisation box and press 'Full scan'.")
        ttk.Label(top, textvariable=self.summary_var, style="Title.TLabel", wraplength=1100).pack(anchor="w")
        cards = ttk.Frame(self.tab_dash)
        cards.pack(fill="x", padx=4, pady=(0, 8))
        self.stat_vars: dict[str, tk.StringVar] = {}
        for i, (key, label) in enumerate((("devices", "Devices online"), ("ports", "Open ports found"),
                                          ("review", "Devices to review"), ("score", "Security score"))):
            card = ttk.Frame(cards, style="Card.TFrame", padding=(18, 12))
            card.grid(row=0, column=i, sticky="ew", padx=5)
            cards.columnconfigure(i, weight=1)
            self.stat_vars[key] = tk.StringVar(value="-")
            ttk.Label(card, textvariable=self.stat_vars[key], style="StatNum.TLabel").pack(anchor="w")
            ttk.Label(card, text=label, style="StatLbl.TLabel").pack(anchor="w")
        self.dash_grid = ttk.Frame(self.tab_dash)
        self.dash_grid.pack(fill="both", expand=True)
        for i in range(2):
            self.dash_grid.columnconfigure(i, weight=1)
            self.dash_grid.rowconfigure(i, weight=1)
        ttk.Label(self.tab_dash, text="Top things to review", style="Title.TLabel").pack(anchor="w", padx=8)
        self.todo = tk.Text(self.tab_dash, height=5, wrap="word", relief="flat", bg=theme.CARD, fg=theme.TEXT,
                            padx=12, pady=8, font=(theme.FONT, 10))
        self.todo.pack(fill="x", padx=8, pady=(0, 6))

    def _put_chart(self, key: str, parent, fig, row=None, col=None):
        old = self._canvases.pop(key, None)
        if old:
            old.get_tk_widget().destroy()
        canvas = FigureCanvasTkAgg(fig, master=parent)
        w = canvas.get_tk_widget()
        if row is not None:
            w.grid(row=row, column=col, sticky="nsew", padx=4, pady=4)
        else:
            w.pack(side="left", fill="both", expand=True, padx=4, pady=4)
        canvas.draw()
        self._canvases[key] = canvas

    def refresh_dashboard(self):
        scan = self.db.latest_scan()
        devices = self.db.list_devices()
        trusted = sum(1 for d in devices if d.online and d.trusted)
        new = sum(1 for d in devices if d.online and not d.trusted)
        off = sum(1 for d in devices if not d.online)
        findings = self.db.findings_for_scan(scan["id"]) if scan else []
        ports = self.db.ports_for_scan(scan["id"]) if scan else []
        score = scan["score"] if scan else 100
        grade = scan["grade"] if scan else "No scan yet"
        if scan:
            self.summary_var.set(f"Last scan {scan['finished']} UTC - {trusted + new} device(s) online, "
                                 f"{scan['open_ports']} open port(s), {new} need review.")
        if scan:
            self.stat_vars["devices"].set(str(trusted + new))
            self.stat_vars["ports"].set(str(scan["open_ports"]))
            self.stat_vars["review"].set(str(new))
            self.stat_vars["score"].set(f"{score}")
        counts = risk.count_by_severity(findings)
        pc = Counter(f"{r['port']}/{r['service'] or '?'}" for r in ports if r["state"] == "open")
        self._put_chart("score", self.dash_grid, charts.figure_score(score, grade), 0, 0)
        self._put_chart("sev", self.dash_grid, charts.figure_severity(counts), 0, 1)
        self._put_chart("dev", self.dash_grid, charts.figure_devices(trusted, new, off), 1, 0)
        self._put_chart("ports", self.dash_grid, charts.figure_ports(pc), 1, 1)
        self.todo.config(state="normal")
        self.todo.delete("1.0", "end")
        top = [f for f in findings if f.severity != "info"][:3]
        if not top:
            self.todo.insert("end", "Nothing urgent to review." if scan else "Run a scan to get recommendations.")
        for f in top:
            self.todo.insert("end", f"- [{f.severity.upper()}] {f.device_name}: {f.title}. {f.recommendation}\n")
        self.todo.config(state="disabled")

    # ------------------------------------------------------------------ devices
    def _build_devices(self):
        bar = ttk.Frame(self.tab_dev, padding=6)
        bar.pack(fill="x")
        for text, cmd in (("Mark as recognised", lambda: self._trust(True)), ("Mark as unrecognised", lambda: self._trust(False)),
                          ("Rename...", self._rename), ("Show open ports", self._show_ports),
                          ("Trust all current devices", self._trust_all), ("Remove record", self._remove)):
            ttk.Button(bar, text=text, command=cmd).pack(side="left", padx=3)
        cols = ("name", "ip", "mac", "vendor", "status", "seen")
        self.dev_tree = ttk.Treeview(self.tab_dev, columns=cols, show="headings", selectmode="browse")
        for c, w, t in zip(cols, (200, 120, 140, 160, 160, 160), ("Name", "IP address", "MAC", "Vendor", "Status", "Last seen")):
            self.dev_tree.heading(c, text=t)
            self.dev_tree.column(c, width=w)
        self.dev_tree.tag_configure("new", background="#ffe9cc")
        self.dev_tree.tag_configure("off", foreground="#888888")
        self.dev_tree.pack(fill="both", expand=True, padx=6, pady=4)
        self.dev_tree.bind("<Double-1>", lambda e: self._show_ports())
        ttk.Label(self.tab_dev, wraplength=1000, text=(
            "A device marked 'New/Unrecognised' may simply be a guest's phone or a new gadget - check before acting. "
            "Devices that are 'Not Currently Detected' may just be asleep or switched off; their records are kept.")
        ).pack(anchor="w", padx=8, pady=4)

    def refresh_devices(self):
        self.dev_tree.delete(*self.dev_tree.get_children())
        for d in self.db.list_devices():
            tag = "new" if d.status == "New/Unrecognised" else "off" if not d.online else ""
            self.dev_tree.insert("", "end", iid=str(d.id), tags=(tag,),
                                 values=(d.display_name, d.ip, d.mac, d.vendor, d.status, d.last_seen))

    def _selected_device(self):
        sel = self.dev_tree.selection()
        if not sel:
            messagebox.showinfo("Select a device", "Please select a device in the list first.")
            return None
        return self.db.get_device(int(sel[0]))

    def _trust(self, value: bool):
        if (d := self._selected_device()):
            self.db.set_trusted(d.id, value)
            self._reassess()

    def _trust_all(self):
        if messagebox.askyesno("Trust all current devices",
                               "Only do this if you have checked the list and recognise every online device.\n\n"
                               "Mark all currently online devices as recognised?"):
            self.db.trust_all_online()
            self._reassess()

    def _rename(self):
        if (d := self._selected_device()):
            name = simpledialog.askstring("Rename device", "Friendly name (e.g. 'Mum's phone'):", initialvalue=d.label, parent=self)
            if name is not None:
                self.db.rename_device(d.id, name)
                self._reassess()

    def _remove(self):
        if (d := self._selected_device()) and messagebox.askyesno("Remove record", f"Remove the saved record for {d.display_name}?\n"
                                                                  "If the device is still on your network it will reappear as new."):
            self.db.remove_device(d.id)
            self.refresh_all()

    def _show_ports(self):
        d = self._selected_device()
        if not d:
            return
        scan = self.db.latest_scan()
        ports = self.db.ports_for_device(scan["id"], d.id) if scan else []
        lines = [f"{p.port}/{p.protocol}  {p.state}  {p.service} {p.banner}".strip() for p in ports] or [
            "No open ports recorded for this device in the latest scan (run a Full scan)."]
        messagebox.showinfo(f"{d.display_name} ({d.ip})", "\n".join(lines))

    def _reassess(self):
        """Re-run the risk engine on the latest scan after the user changes device trust/names."""
        scan = self.db.latest_scan()
        if scan:
            devices = self.db.list_devices()
            ports = {d.id: self.db.ports_for_device(scan["id"], d.id) for d in devices if d.online}
            findings = risk.analyse(devices, ports)
            with self.db.tx() as c:
                c.execute("DELETE FROM findings WHERE scan_id=?", (scan["id"],))
            self.db.save_findings(scan["id"], findings)
            score, grade = risk.security_score(findings)
            new = sum(1 for d in devices if d.online and not d.trusted)
            self.db.finish_scan(scan["id"], score=score, grade=grade, new_devices=new)
        self.refresh_all()

    # ------------------------------------------------------------------ findings
    def _build_findings(self):
        bar = ttk.Frame(self.tab_find, padding=6)
        bar.pack(fill="x")
        ttk.Label(bar, text="Show:").pack(side="left")
        self.sev_filter = tk.StringVar(value="low")
        cb = ttk.Combobox(bar, textvariable=self.sev_filter, values=SEVERITIES, state="readonly", width=10)
        cb.pack(side="left", padx=4)
        cb.bind("<<ComboboxSelected>>", lambda e: self.refresh_findings())
        ttk.Label(bar, text="and above").pack(side="left")
        cols = ("sev", "device", "title", "port")
        self.find_tree = ttk.Treeview(self.tab_find, columns=cols, show="headings", height=12, selectmode="browse")
        for c, w, t in zip(cols, (90, 200, 560, 70), ("Severity", "Device", "What we found", "Port")):
            self.find_tree.heading(c, text=t)
            self.find_tree.column(c, width=w)
        for s, bg in SEV_BG.items():
            self.find_tree.tag_configure(s, background=bg)
        self.find_tree.pack(fill="both", expand=True, padx=6)
        self.find_tree.bind("<<TreeviewSelect>>", self._show_finding)
        self.find_detail = tk.Text(self.tab_find, height=8, wrap="word", state="disabled", padx=12, pady=8,
                                   relief="flat", bg=theme.CARD, font=(theme.FONT, 10))
        self.find_detail.pack(fill="x", padx=6, pady=6)
        self._findings_cache: dict[str, object] = {}

    def refresh_findings(self):
        self.find_tree.delete(*self.find_tree.get_children())
        self._findings_cache.clear()
        scan = self.db.latest_scan()
        if not scan:
            return
        floor = SEVERITY_RANK[self.sev_filter.get()]
        for i, f in enumerate(self.db.findings_for_scan(scan["id"])):
            if SEVERITY_RANK[f.severity] < floor:
                continue
            self._findings_cache[str(i)] = f
            self.find_tree.insert("", "end", iid=str(i), tags=(f.severity,),
                                  values=(f.severity.upper(), f.device_name, f.title, f.port or ""))

    def _show_finding(self, _evt=None):
        sel = self.find_tree.selection()
        if not sel:
            return
        f = self._findings_cache[sel[0]]
        self.find_detail.config(state="normal")
        self.find_detail.delete("1.0", "end")
        self.find_detail.insert("end", f"{f.title}\n\n{f.description}\n\nSuggested next step:\n{f.recommendation}")
        self.find_detail.config(state="disabled")

    # ------------------------------------------------------------------ traffic
    def _build_traffic(self):
        bar = ttk.Frame(self.tab_traffic, padding=6)
        bar.pack(fill="x")
        ttk.Label(bar, text="Interface:").pack(side="left")
        self.iface_var = tk.StringVar()
        ttk.Entry(bar, textvariable=self.iface_var, width=16).pack(side="left", padx=4)
        ttk.Label(bar, text="Seconds:").pack(side="left")
        self.secs_var = tk.IntVar(value=20)
        ttk.Spinbox(bar, from_=5, to=300, textvariable=self.secs_var, width=5).pack(side="left", padx=4)
        ttk.Button(bar, text="Capture live traffic", command=self.start_capture).pack(side="left", padx=6)
        ttk.Button(bar, text="Analyse .pcap file...", command=self.analyse_pcap).pack(side="left")
        ttk.Label(self.tab_traffic, wraplength=1050, text=(
            "Traffic analysis is optional and needs Wireshark/tshark plus permission to capture packets "
            "(administrator/root). Only packet headers (who talked to whom, protocol, size) are examined - "
            "message content is never read or stored.")).pack(anchor="w", padx=8)
        self.traffic_info = tk.StringVar(value="No traffic captured yet.")
        ttk.Label(self.tab_traffic, textvariable=self.traffic_info, style="Title.TLabel").pack(anchor="w", padx=8, pady=4)
        self.traffic_charts = ttk.Frame(self.tab_traffic)
        self.traffic_charts.pack(fill="both", expand=True)
        self.traffic_text = tk.Text(self.tab_traffic, height=7, wrap="word", state="disabled", padx=12, pady=8,
                                    relief="flat", bg=theme.CARD, font=(theme.FONT, 10))
        self.traffic_text.pack(fill="x", padx=6, pady=6)

    def refresh_traffic(self):
        t = self.db.latest_traffic()
        for k in ("proto", "talk"):
            c = self._canvases.pop(k, None)
            if c:
                c.get_tk_widget().destroy()
        self.traffic_text.config(state="normal")
        self.traffic_text.delete("1.0", "end")
        if not t:
            self.traffic_text.config(state="disabled")
            return
        s = t["summary"]
        self.traffic_info.set(f"{s['packets']:,} packets / {s['bytes']:,} bytes ({t['source']}) at {t['started']} UTC")
        self._put_chart("proto", self.traffic_charts, charts.figure_protocols(s["protocols"]))
        self._put_chart("talk", self.traffic_charts, charts.figure_talkers(s["top_talkers"]))
        fl = s.get("findings", [])
        self.traffic_text.insert("end", "\n\n".join(f"[{f['severity'].upper()}] {f['title']}\n{f['description']}\n-> {f['recommendation']}"
                                                    for f in fl) or "No unusual patterns were seen in this capture.")
        self.traffic_text.config(state="disabled")

    # ------------------------------------------------------------------ history
    def _build_history(self):
        cols = ("when", "net", "kind", "devices", "ports", "score")
        self.hist_tree = ttk.Treeview(self.tab_hist, columns=cols, show="headings", height=8)
        for c, w, t in zip(cols, (180, 140, 80, 90, 90, 90), ("Finished (UTC)", "Network", "Type", "Devices", "Open ports", "Score")):
            self.hist_tree.heading(c, text=t)
            self.hist_tree.column(c, width=w)
        self.hist_tree.pack(fill="x", padx=6, pady=6)
        self.hist_chart = ttk.Frame(self.tab_hist)
        self.hist_chart.pack(fill="both", expand=True)

    def refresh_history(self):
        self.hist_tree.delete(*self.hist_tree.get_children())
        scans = self.db.scan_history()
        for s in scans:
            self.hist_tree.insert("", "end", values=(s["finished"], s["network"], s["kind"], s["hosts_found"], s["open_ports"], s["score"]))
        self._put_chart("hist", self.hist_chart, charts.figure_history(scans))

    # ------------------------------------------------------------------ actions
    def refresh_all(self):
        self.refresh_dashboard()
        self.refresh_devices()
        self.refresh_findings()
        self.refresh_traffic()
        self.refresh_history()

    def _require_auth(self) -> bool:
        if not self.auth_var.get():
            messagebox.showwarning("Authorisation needed", "Please confirm that you own this network or are authorised "
                                   "to assess it before scanning or capturing traffic.")
            return False
        return True

    def _run_bg(self, fn, on_done, label: str):
        if self.busy:
            return
        self.busy = True
        self.stop_flag.clear()
        self._set_busy(True)
        self.status_var.set(label)

        def worker():
            try:
                self.q.put(("done", on_done, fn()))
            except Exception as exc:     # shown to the user, never silently swallowed
                self.q.put(("error", None, exc))
        threading.Thread(target=worker, daemon=True).start()

    def _set_busy(self, busy: bool):
        for b in self.btns:
            b.config(state="disabled" if busy else "normal")
        self.stop_btn.config(state="normal" if busy else "disabled")
        self.progress.config(mode="determinate")
        if not busy:
            self.progress["value"] = 0

    def _progress_cb(self, msg: str, frac: float):
        self.q.put(("progress", msg, frac))

    def start_scan(self, deep: bool):
        if not self._require_auth():
            return
        net = self.net_var.get()
        try:
            config.validate_network(net)
        except config.NetworkNotAllowed as exc:
            messagebox.showerror("Network not allowed", str(exc))
            return
        self._run_bg(lambda: self.svc.run_scan(net, deep, self._progress_cb, self.stop_flag.is_set),
                     self._scan_done, "Scanning ...")

    def _scan_done(self, res):
        self.refresh_all()
        self.nb.select(self.tab_dash)
        msg = f"Scan complete: {res.hosts_found} device(s), score {res.score}/100 ({res.grade})."
        if res.warnings:
            msg += "  Note: " + " ".join(res.warnings)
        self.status_var.set(msg)
        if res.new_devices and not self.demo:
            self.nb.select(self.tab_dev)
            messagebox.showinfo("Devices to review", f"{res.new_devices} device(s) are not yet marked as recognised.\n"
                                "Review them in the Devices tab - they may belong to you, family or guests.")

    def start_capture(self):
        if not self._require_auth():
            return
        iface, secs = self.iface_var.get().strip(), int(self.secs_var.get())
        if self.svc.monitor is None:
            messagebox.showerror("Traffic analysis unavailable", "PyShark/Wireshark is not installed. Install them and restart.")
            return
        self._run_bg(lambda: self.svc.run_traffic(iface, secs, None, lambda n: self._progress_cb(f"Captured {n} packets ...", 0.5),
                                                  self.stop_flag.is_set),
                     self._traffic_done, f"Capturing traffic for {secs}s ...")

    def analyse_pcap(self):
        path = filedialog.askopenfilename(title="Choose a capture file", filetypes=[("Capture files", "*.pcap *.pcapng"), ("All", "*.*")])
        if path and self.svc.monitor is not None and self._require_auth():
            self._run_bg(lambda: self.svc.run_traffic("", 0, path), self._traffic_done, "Analysing capture file ...")

    def _traffic_done(self, _res):
        self.refresh_traffic()
        self.nb.select(self.tab_traffic)
        self.status_var.set("Traffic analysis complete.")

    def export_report(self):
        try:
            out = build_report(self.db, config.REPORT_DIR / f"report-{datetime.now():%Y%m%d-%H%M%S}.html")
        except RuntimeError as exc:
            messagebox.showinfo("No report yet", str(exc))
            return
        self.status_var.set(f"Report saved to {out}")
        if messagebox.askyesno("Report saved", f"Saved to:\n{out}\n\nOpen it now?"):
            webbrowser.open(out.as_uri())

    def _poll(self):
        try:
            while True:
                kind, a, b = self.q.get_nowait()
                if kind == "progress":
                    self.status_var.set(a)
                    self.progress["value"] = b * 100
                elif kind == "done":
                    self.busy = False
                    self._set_busy(False)
                    a(b)
                elif kind == "error":
                    self.busy = False
                    self._set_busy(False)
                    self.status_var.set("Something went wrong.")
                    messagebox.showerror("Could not complete the task", str(b))
        except queue.Empty:
            pass
        self.after(100, self._poll)


def run_gui(demo: bool = False) -> None:
    App(demo=demo).mainloop()
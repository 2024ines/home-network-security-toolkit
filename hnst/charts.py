"""Matplotlib charts shared by the Tkinter dashboard and the HTML report."""
from __future__ import annotations

from matplotlib.figure import Figure

SEV_COLORS = {"critical": "#b71c1c", "high": "#e53935", "medium": "#fb8c00", "low": "#fdd835", "info": "#90a4ae"}


def score_colour(score: int) -> str:
    return "#2e7d32" if score >= 90 else "#f9a825" if score >= 70 else "#ef6c00" if score >= 50 else "#c62828"


def figure_score(score: int, grade: str, size=(3.2, 2.6)) -> Figure:
    fig = Figure(figsize=size, dpi=100)
    ax = fig.add_subplot(111, aspect="equal")
    ax.pie([score, 100 - score], startangle=90, counterclock=False, colors=[score_colour(score), "#e0e0e0"],
           wedgeprops=dict(width=0.32))
    ax.text(0, 0.05, str(score), ha="center", va="center", fontsize=26, fontweight="bold")
    ax.text(0, -0.28, "/ 100", ha="center", va="center", fontsize=9, color="#555")
    ax.set_title(grade, fontsize=10, pad=4)
    fig.tight_layout()
    return fig


def figure_severity(counts: dict[str, int], size=(3.6, 2.6)) -> Figure:
    fig = Figure(figsize=size, dpi=100)
    ax = fig.add_subplot(111)
    labels = ["critical", "high", "medium", "low", "info"]
    vals = [counts.get(k, 0) for k in labels]
    ax.bar(labels, vals, color=[SEV_COLORS[k] for k in labels])
    for i, v in enumerate(vals):
        ax.text(i, v + 0.05, str(v), ha="center", fontsize=9)
    ax.set_title("Findings by severity", fontsize=10)
    ax.spines[["top", "right"]].set_visible(False)
    ax.yaxis.get_major_locator().set_params(integer=True)
    fig.tight_layout()
    return fig


def figure_devices(online: int, new: int, offline: int, size=(3.2, 2.6)) -> Figure:
    fig = Figure(figsize=size, dpi=100)
    ax = fig.add_subplot(111)
    data = [(online, "Recognised", "#43a047"), (new, "New/Unrecognised", "#fb8c00"), (offline, "Not detected", "#9e9e9e")]
    data = [d for d in data if d[0] > 0]
    if data:
        ax.pie([d[0] for d in data], labels=[f"{d[1]} ({d[0]})" for d in data], colors=[d[2] for d in data],
               textprops={"fontsize": 8}, startangle=90)
    else:
        ax.text(0.5, 0.5, "No devices yet", ha="center")
        ax.axis("off")
    ax.set_title("Devices", fontsize=10)
    fig.tight_layout()
    return fig


def figure_ports(port_counts: dict[str, int], size=(3.6, 2.6)) -> Figure:
    fig = Figure(figsize=size, dpi=100)
    ax = fig.add_subplot(111)
    items = sorted(port_counts.items(), key=lambda kv: -kv[1])[:8]
    if items:
        ax.barh([k for k, _ in items][::-1], [v for _, v in items][::-1], color="#1e88e5")
        ax.xaxis.get_major_locator().set_params(integer=True)
    else:
        ax.text(0.5, 0.5, "No open ports recorded", ha="center")
        ax.axis("off")
    ax.set_title("Most common open ports", fontsize=10)
    ax.tick_params(labelsize=8)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    return fig


def figure_protocols(protocols: dict[str, int], size=(3.8, 2.8)) -> Figure:
    fig = Figure(figsize=size, dpi=100)
    ax = fig.add_subplot(111)
    if protocols:
        ax.pie(list(protocols.values()), labels=list(protocols.keys()), textprops={"fontsize": 8}, startangle=90)
    ax.set_title("Protocols seen", fontsize=10)
    fig.tight_layout()
    return fig


def figure_talkers(talkers: list[dict], size=(3.8, 2.8)) -> Figure:
    fig = Figure(figsize=size, dpi=100)
    ax = fig.add_subplot(111)
    if talkers:
        names = [t["ip"] for t in talkers][::-1]
        ax.barh(names, [t["packets"] for t in talkers][::-1], color="#5e35b1")
    ax.set_title("Top talkers (packets)", fontsize=10)
    ax.tick_params(labelsize=8)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    return fig


def figure_history(scans: list, size=(4.6, 2.4)) -> Figure:
    """Security score over time (oldest -> newest)."""
    fig = Figure(figsize=size, dpi=100)
    ax = fig.add_subplot(111)
    scans = list(reversed(scans))
    if scans:
        ax.plot(range(1, len(scans) + 1), [s["score"] for s in scans], marker="o", color="#1e88e5")
        ax.set_xticks(range(1, len(scans) + 1))
    ax.set_ylim(0, 105)
    ax.set_title("Security score over time", fontsize=10)
    ax.set_xlabel("Scan #", fontsize=8)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    return fig
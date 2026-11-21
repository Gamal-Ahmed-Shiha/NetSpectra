import os

import numpy as np
import pandas as pd

from . import COLOR_ORANGE, COLOR_RED, COLOR_TEAL, RESULTS_DIR, apply_dark_style

# (minimum ratio of peak / normal, label) — first match wins
SEVERITY_LEVELS = ((8.0, "CRITICAL"), (4.0, "HIGH"), (1.0, "MEDIUM"))

MAX_PRINTED_EVENTS = 15


def severity_of(ratio):
    for min_ratio, label in SEVERITY_LEVELS:
        if ratio >= min_ratio:
            return label
    return "MEDIUM"


def rank_cap(n, top_pct):
    return max(1, int(np.ceil(n * float(top_pct) / 100.0)))


def _mask_from(hits, n):
    mask = np.zeros(n, dtype=bool)
    mask[np.asarray(hits, dtype=int)] = True
    return mask


def run(signal, time_axis=None, top_pct=1.0, exaggeration=5.0):
    s = np.asarray(signal, dtype=float)
    if s.size == 0:
        raise ValueError("The signal is empty — run Signal Generation first.")
    if time_axis is None:
        time_axis = np.arange(len(s), dtype=float)
    time_axis = np.asarray(time_axis, dtype=float)

    n = len(s)
    normal = float(np.median(s))              
    if normal <= 0:
        normal = float(np.mean(s))            
    exag_level = (float(exaggeration) * normal) if normal > 0 else float("inf")

    cap = rank_cap(n, top_pct)
    order = np.lexsort((np.arange(n), -s))[:cap]
    hits = np.sort(order[s[order] >= exag_level])

    groups = (np.split(hits, np.where(np.diff(hits) > 1)[0] + 1)
              if hits.size else [])
    events = []
    for g in groups:
        i0, i1 = int(g[0]), int(g[-1])
        peak = float(np.max(s[i0:i1 + 1]))
        ratio = peak / normal if normal > 0 else float("inf")
        events.append({
            "start_index": i0,
            "end_index": i1,
            "start_time": float(time_axis[i0]),
            "end_time": float(time_axis[i1]),
            "duration": i1 - i0 + 1,              
            "peak": int(round(peak)),            
            "total_packets": int(round(np.sum(s[i0:i1 + 1]))),
            "ratio": float(ratio),                  
            "severity": severity_of(ratio),
        })
    events.sort(key=lambda e: e["peak"], reverse=True)  

    flagged = int(hits.size)
    pct = 100.0 * flagged / n
    print("Normal level (median of the capture): {:.2f} pkt/s".format(normal))
    if np.isfinite(exag_level):
        print("Flag line: {} x median = {:.2f} pkt/s — only a gross "
              "exaggeration of the normal traffic is suspicious".format(
                  exaggeration, exag_level))
    print("Rank cap: only the highest {:.2f}% of seconds ({} of {}) can "
          "ever be flagged".format(top_pct, cap, n))
    print("Flagged seconds: {} of {} ({:.2f}%)".format(flagged, n, pct))
    print("Events detected: {}".format(len(events)))
    for i, e in enumerate(events[:MAX_PRINTED_EVENTS], 1):
        print("  #{i}: t={t0:.0f}s -> {t1:.0f}s | dur={d}s | peak={p} pkt/s"
              " | {r:.1f}x normal | {sev}".format(
                  i=i, t0=e["start_time"], t1=e["end_time"], d=e["duration"],
                  p=e["peak"], r=e["ratio"], sev=e["severity"]))
    if len(events) > MAX_PRINTED_EVENTS:
        print("  ... + {} more — the full list is in ddos_events.csv".format(
            len(events) - MAX_PRINTED_EVENTS))
    if not events:
        print("No extreme peaks — nothing in this traffic looks like an attack.")

    csv_path = None
    if events:
        df = pd.DataFrame([{
            "Event_ID": i,
            "Start_Time_s": round(e["start_time"], 1),
            "End_Time_s": round(e["end_time"], 1),
            "Duration_s": e["duration"],
            "Peak_Packets_Per_Second": e["peak"],
            "Total_Packets": e["total_packets"],
            "Ratio_To_Normal": round(e["ratio"], 2),
            "Severity": e["severity"],
        } for i, e in enumerate(events, 1)])
        csv_path = os.path.join(RESULTS_DIR, "ddos_events.csv")
        df.to_csv(csv_path, index=False)
        print("Events table saved at:", csv_path)

    return {
        "top_pct": float(top_pct),
        "exaggeration": float(exaggeration),
        "normal": normal,
        "exag_level": exag_level,
        "max_flagged": cap,
        "mask": _mask_from(hits, n),
        "events": events,
        "time_axis": time_axis,
        "attacked_seconds": flagged,
        "attacked_ratio_pct": pct,
        "csv_path": csv_path,
    }


def plot_detection(signal, result, time_axis=None, view=None):
    apply_dark_style()
    import matplotlib.pyplot as plt

    from . import apply_view, draw_discrete, view_note

    s = np.asarray(signal, dtype=float)
    if time_axis is None:
        time_axis = result["time_axis"]
    t_v, s_v, m = apply_view(np.asarray(time_axis, dtype=float), s, view)
    mask_v = np.asarray(result["mask"], dtype=bool)[m]

    fig, ax = plt.subplots(figsize=(7.6, 4.4), constrained_layout=True)
    used = draw_discrete(ax, t_v, s_v, color=COLOR_TEAL, label="Packet Rate")
    if np.isfinite(result["exag_level"]):
        ax.axhline(result["exag_level"], color=COLOR_ORANGE, linestyle="--",
                   linewidth=1.6,
                   label="Flag line = {:.0f} × median = {:.1f}".format(
                       result["exaggeration"], result["exag_level"]))
    if np.any(mask_v):
        ax.plot(t_v[mask_v], s_v[mask_v], linestyle="None", marker="o",
                markersize=6.0, markerfacecolor="none",
                markeredgecolor=COLOR_RED, markeredgewidth=1.5,
                label="Extreme peaks (flagged)")
    for e in result["events"]:                    # red band over each event
        if e["end_time"] >= t_v[0] and e["start_time"] <= t_v[-1]:
            ax.axvspan(e["start_time"], e["end_time"] + 1.0, color=COLOR_RED,
                       alpha=0.14, linewidth=0)

    note = view_note(len(s_v), used)
    title = "DDoS Detection"
    if note:
        title += "   ({})".format(note)
    ax.set_title(title)
    ax.set_xlabel("Time (Seconds)")
    ax.set_ylabel("Packets per Second")
    ax.legend(loc="upper right")
    return fig

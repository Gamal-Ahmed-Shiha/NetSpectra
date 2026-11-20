"""Network DSP — operations package.

Shared helpers used by every operation module:
  - Project folder constants (PCAPS_DIR, RESULTS_DIR, PLOTS_DIR)
  - The dark "black x teal" color palette
  - apply_dark_style(): matplotlib rcParams matching the UI theme
  - draw_discrete(): draws a DISCRETE signal as vertical lines (stems for
    short windows, needle lines for full overviews) — never a smooth curve
  - apply_view() / view_note(): zoom helpers for long recordings
  - save_figure(): exports a figure as a PNG into results/plots/
"""

import os

import numpy as np

# ------------------------------------------------------------- folders
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PCAPS_DIR = os.path.join(BASE_DIR, "pcaps")
RESULTS_DIR = os.path.join(BASE_DIR, "results")
PLOTS_DIR = os.path.join(RESULTS_DIR, "plots")

for _d in (PCAPS_DIR, RESULTS_DIR, PLOTS_DIR):
    os.makedirs(_d, exist_ok=True)

# ------------------------------------------------------------- palette
COLOR_TEAL = "#00e5cc"    # primary signal color
COLOR_ORANGE = "#ffb454"  # secondary / thresholds
COLOR_RED = "#ff5c5d"     # attacks, errors
COLOR_BLUE = "#4da3ff"    # extra series
COLOR_GREEN = "#39d98a"   # ok states
COLOR_TEXT = "#dce6f2"    # plot text
COLOR_MUTED = "#8fa0b3"   # axis labels
COLOR_BG = "#0d1520"      # plot background (matches the UI plot card)
COLOR_EDGE = "#2a3950"    # spines
COLOR_GRID = "#22304a"    # grid lines

# ------------------------------------------------------------- style


def apply_dark_style():
    """Applies the global dark matplotlib theme (black background, teal /
    light text) so every exported figure blends into the UI."""
    import matplotlib as mpl

    mpl.rcParams.update({
        "figure.facecolor": COLOR_BG,
        "axes.facecolor": COLOR_BG,
        "savefig.facecolor": COLOR_BG,
        "text.color": COLOR_TEXT,
        "axes.labelcolor": COLOR_MUTED,
        "axes.edgecolor": COLOR_EDGE,
        "axes.titlecolor": COLOR_TEXT,
        "axes.titleweight": "bold",
        "axes.grid": True,
        "grid.color": COLOR_GRID,
        "grid.alpha": 0.55,
        "grid.linewidth": 0.7,
        "xtick.color": COLOR_MUTED,
        "ytick.color": COLOR_MUTED,
        "font.family": "DejaVu Sans",
        "font.size": 10,
        "axes.titlesize": 11.5,
        "axes.titlepad": 8,
        "legend.frameon": False,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.prop_cycle": mpl.cycler(
            color=[COLOR_TEAL, COLOR_ORANGE, COLOR_BLUE, COLOR_RED, COLOR_GREEN]
        ),
    })


# ----------------------------------------------------- discrete drawing


def draw_discrete(ax, t, s, color=COLOR_TEAL, label=None, max_needles=4000,
                  marker=False, marker_size=5.0):
    """Draws the DISCRETE signal as one vertical line per sample.

    Short windows (<= 400 samples) are drawn as a classic stem plot; long
    windows become thin needle lines (optionally downsampled so the figure
    stays fast and readable). With marker=True a clear circle is placed on
    the tip of EVERY drawn sample, on top of the stems / needles — used by
    the Signal Generation plots. Returns the number of samples actually
    drawn so callers can build a note with view_note().
    """
    import matplotlib.pyplot as plt

    t = np.asarray(t, dtype=float)
    s = np.asarray(s, dtype=float)
    n = len(s)

    if n <= 400:
        markerline, stemlines, baseline = ax.stem(t, s, basefmt=" ")
        stemlines.set_color(color)
        stemlines.set_linewidth(1.1)
        stemlines.set_alpha(0.9)
        markerline.set_color(color)
        markerline.set_markersize(4.2)
        baseline.set_visible(False)
        if marker:
            # bigger circles on top of every stem; the legend entry becomes
            # the circle itself instead of the tiny stem head
            markerline.set_visible(False)
            ax.plot(t, s, linestyle="None", marker="o",
                    markersize=marker_size, markerfacecolor=color,
                    markeredgecolor=color, alpha=0.95, label=label)
        elif label:
            markerline.set_label(label)
        plt.setp(markerline, linestyle="None")
        return n

    step = max(1, int(np.ceil(n / max_needles)))
    t_d, s_d = t[::step], s[::step]
    ax.vlines(t_d, 0, s_d, color=color, linewidth=0.6, alpha=0.95)
    # a circle on the tip of every drawn line (bigger when marker=True)
    ax.plot(t_d, s_d, linestyle="None", marker="o",
            markersize=marker_size if marker else 2.6,
            markerfacecolor=color, markeredgecolor=color, alpha=0.9,
            label=label)
    return int(len(t_d))


def view_note(n_total, n_drawn):
    """Human note for downsampled overviews; empty string when everything
    was drawn."""
    if n_drawn >= n_total:
        return ""
    return "showing {:,}/{:,}".format(n_drawn, n_total)


def apply_view(time_axis, signal, view=None):
    """Zoom helper.

    view is one of:
      None                -> the full signal
      ("first", seconds)  -> samples from the beginning
      ("last",  seconds)  -> samples until the end
      (t0, t1)            -> an explicit time range

    Returns (t_view, s_view, index_mask).
    """
    t = np.asarray(time_axis, dtype=float)
    s = np.asarray(signal, dtype=float)

    if view is None:
        mask = np.ones(len(t), dtype=bool)
    elif isinstance(view, tuple) and len(view) == 2:
        kind, value = view
        if isinstance(kind, str) and kind == "first":
            mask = t <= t[0] + float(value)
        elif isinstance(kind, str) and kind == "last":
            mask = t >= t[-1] - float(value)
        else:
            mask = (t >= float(kind)) & (t <= float(value))
    else:
        mask = np.ones(len(t), dtype=bool)

    return t[mask], s[mask], mask


# ------------------------------------------------------------- export


def save_figure(fig, name):
    """Saves the figure into results/plots/<name>.png and returns the path."""
    path = os.path.join(PLOTS_DIR, name + ".png")
    fig.savefig(path, dpi=150, facecolor=fig.get_facecolor())
    print("Figure saved at:", path)
    return path

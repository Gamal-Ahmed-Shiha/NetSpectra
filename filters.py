import os
import numpy as np
import pandas as pd
from . import COLOR_ORANGE, COLOR_TEAL, RESULTS_DIR, apply_dark_style


def run(signal, window_size=5, time_axis=None):
    signal = np.asarray(signal, dtype=float)
    window_size = int(window_size)
    if window_size < 1:
        raise ValueError("Window size must be at least 1.")

    h = np.ones(window_size) / window_size

    filtered_full = np.convolve(signal, h, mode="full")
    filtered_signal = filtered_full[: len(signal)]  

    csv_path = os.path.join(RESULTS_DIR, "filtered_signal.csv")
    if time_axis is None:
        time_axis = np.arange(len(signal), dtype=float)
    pd.DataFrame({
        "Time": np.asarray(time_axis, dtype=float)[: len(signal)],
        "Filtered_Count": filtered_signal,
    }).round(4).to_csv(csv_path, index=False)

    print("Window Size:", window_size)
    print("Kernel:", h)
    print("Original Signal Length:", len(signal))
    print("Filtered Signal Length:", len(filtered_signal))
    print("Mean Before Filter: {:.4f}".format(float(np.mean(signal))))
    print("Mean After Filter: {:.4f}".format(float(np.mean(filtered_signal))))
    print("Filtered signal saved at:", csv_path)

    return {
        "h": h,
        "window_size": window_size,
        "filtered_signal": filtered_signal,
        "csv_path": csv_path,
    }


def plot_filter_comparison(signal, filtered_signal, time_axis=None, first_n=100):
    apply_dark_style()
    import matplotlib.pyplot as plt

    if time_axis is None:
        time_axis = np.arange(len(signal), dtype=float)

    n = min(first_n, len(signal))
    t = np.asarray(time_axis, dtype=float)[:n]
    x = np.asarray(signal, dtype=float)[:n]
    y = np.asarray(filtered_signal, dtype=float)[:n]

    fig, ax = plt.subplots(figsize=(7.6, 4.4), constrained_layout=True)

    m1, sl1, _ = ax.stem(t, x, basefmt=" ")
    sl1.set_color(COLOR_TEAL); sl1.set_linewidth(1.2); sl1.set_alpha(0.85)
    m1.set_color(COLOR_TEAL); m1.set_markersize(4); m1.set_label("Original Signal")

    m2, sl2, _ = ax.stem(t, y, basefmt=" ")
    sl2.set_color(COLOR_ORANGE); sl2.set_linewidth(1.2); sl2.set_alpha(0.85)
    m2.set_color(COLOR_ORANGE); m2.set_markersize(4)
    m2.set_label("Moving Average Filtered Signal")

    ax.set_title("Moving Average Filter using Linear Convolution")
    ax.set_xlabel("Time (Seconds)")
    ax.set_ylabel("Packets per Second")
    ax.legend(loc="upper right")

    return fig

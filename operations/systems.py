import os
import numpy as np
import pandas as pd
from . import COLOR_ORANGE, COLOR_TEAL, RESULTS_DIR, apply_dark_style


def run(signal, a=0.5, b=0.5, time_axis=None):
    signal = np.asarray(signal, dtype=float)

    difference_output = np.zeros(len(signal))
    for n in range(len(signal)):
        previous_output = 0 if n == 0 else difference_output[n - 1]
        difference_output[n] = a * signal[n] + b * previous_output

    csv_path = os.path.join(RESULTS_DIR, "difference_output.csv")
    if time_axis is None:
        time_axis = np.arange(len(signal), dtype=float)
    pd.DataFrame({
        "Time": np.asarray(time_axis, dtype=float)[: len(signal)],
        "Difference_Output": difference_output,
    }).round(4).to_csv(csv_path, index=False)

    print("Coefficients: a = {} , b = {}".format(a, b))
    print("Original Signal Length:", len(signal))
    print("Output Signal Length:", len(difference_output))
    print("Original Mean: {:.4f}".format(float(np.mean(signal))))
    print("Output Mean: {:.4f}".format(float(np.mean(difference_output))))
    print("Maximum Output: {:.4f}".format(float(np.max(difference_output))))
    print("Output saved at:", csv_path)

    return {
        "a": float(a),
        "b": float(b),
        "difference_output": difference_output,
        "csv_path": csv_path,
    }


def plot_system_comparison(signal, difference_output, time_axis=None,
                           first_n=100):
    apply_dark_style()
    import matplotlib.pyplot as plt

    if time_axis is None:
        time_axis = np.arange(len(signal), dtype=float)

    n = min(first_n, len(signal))
    t = np.asarray(time_axis, dtype=float)[:n]
    x = np.asarray(signal, dtype=float)[:n]
    y = np.asarray(difference_output, dtype=float)[:n]

    fig, ax = plt.subplots(figsize=(7.6, 4.4), constrained_layout=True)

    m1, sl1, _ = ax.stem(t, x, basefmt=" ")
    sl1.set_color(COLOR_TEAL); sl1.set_linewidth(1.2); sl1.set_alpha(0.85)
    m1.set_color(COLOR_TEAL); m1.set_markersize(4); m1.set_label("Original Signal")

    m2, sl2, _ = ax.stem(t, y, basefmt=" ")
    sl2.set_color(COLOR_ORANGE); sl2.set_linewidth(1.2); sl2.set_alpha(0.85)
    m2.set_color(COLOR_ORANGE); m2.set_markersize(4)
    m2.set_label("First-Order Difference Output")

    ax.set_title("First-Order Difference Equation: y[n] = a·x[n] + b·y[n-1]")
    ax.set_xlabel("Time (Seconds)")
    ax.set_ylabel("Amplitude")
    ax.legend(loc="upper right")

    return fig

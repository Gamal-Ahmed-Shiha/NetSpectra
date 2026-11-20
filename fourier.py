import os
import numpy as np
import pandas as pd

from . import COLOR_ORANGE, COLOR_TEAL, RESULTS_DIR, apply_dark_style


def run(signal, ts=1.0):
    signal = np.asarray(signal, dtype=float)

    N = len(signal)
    Ts = float(ts)
    Fs = 1.0 / Ts
    signal_mean = float(np.mean(signal))
    
    signal_ac = signal - signal_mean          

    X = np.fft.fft(signal_ac)
    X_shifted = np.fft.fftshift(X)

    frequencies = np.fft.fftshift(np.fft.fftfreq(N, d=Ts))
    magnitude = np.abs(X_shifted)
    phase = np.angle(X_shifted)

    csv_path = os.path.join(RESULTS_DIR, "fourier_spectrum.csv")
    pd.DataFrame({
        "Frequency_Hz": frequencies,
        "Magnitude": magnitude,
        "Phase_Rad": phase,
    }).round(6).to_csv(csv_path, index=False)

    resolution = Fs / N

    print("Signal Length:", N)
    print("Sampling Frequency: {} Hz".format(Fs))
    print("Frequency Resolution: {:.6g} Hz".format(resolution))
    print("Original Signal Mean (DC): {:.4f}".format(signal_mean))
    print("Mean After DC Removal: {:.3e}".format(float(np.mean(signal_ac))))
    print("Spectrum saved at:", csv_path)

    return {
        "N": N,
        "fs": Fs,
        "resolution": resolution,
        "mean": signal_mean,
        "frequencies": frequencies,
        "magnitude": magnitude,
        "phase": phase,
        "csv_path": csv_path,
    }


def plot_spectrum(result, max_points=20000):
    apply_dark_style()
    import matplotlib.pyplot as plt

    freq = result["frequencies"]
    mag = result["magnitude"]
    pha = result["phase"]

    if len(freq) > max_points:
        step = int(np.ceil(len(freq) / max_points))
        freq, mag, pha = freq[::step], mag[::step], pha[::step]

    fig, axes = plt.subplots(2, 1, figsize=(7.6, 6.4), constrained_layout=True)

    axes[0].plot(freq, mag, color=COLOR_TEAL, linewidth=1.0)
    axes[0].set_title("DTFT — Magnitude Spectrum (DC Removed)")
    axes[0].set_xlabel("Frequency (Hz)")
    axes[0].set_ylabel("Magnitude")

    axes[1].plot(freq, pha, color=COLOR_ORANGE, linewidth=0.8)
    axes[1].set_title("DTFT — Phase Spectrum (DC Removed)")
    axes[1].set_xlabel("Frequency (Hz)")
    axes[1].set_ylabel("Phase (Radians)")

    return fig

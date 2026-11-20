import os
import numpy as np
import pandas as pd
from . import RESULTS_DIR


def run(pcap_path, sampling_interval=1.0):
    from scapy.all import PcapReader

    if not pcap_path:
        raise ValueError(
            "No PCAP loaded — click Upload PCAP first, or drop a capture "
            "file into the pcaps/ folder and restart the app."
        )
    if not os.path.isfile(pcap_path):
        raise FileNotFoundError(
            "The capture file does not exist: " + str(pcap_path)
        )

    print("Reading capture:", pcap_path)
    
    timestamps = []
    with PcapReader(pcap_path) as reader:
        for packet in reader:
            timestamps.append(float(packet.time))
    if len(timestamps) == 0:
        raise ValueError("The capture contains no packets.")

    timestamps = np.array(timestamps)
    relative_time = timestamps - timestamps[0]

    num_bins = int(np.ceil(relative_time[-1] / sampling_interval))
    num_bins = max(num_bins, 1)

    signal, _ = np.histogram(
        relative_time,
        bins=num_bins,
        range=(0, num_bins * sampling_interval),
    )
    time_axis = np.arange(num_bins) * sampling_interval

    csv_path = os.path.join(RESULTS_DIR, "network_signal.csv")
    pd.DataFrame({
        "Time": time_axis,
        "Packet_Count": signal,
    }).to_csv(csv_path, index=False)

    stats = {
        "total_packets": len(timestamps),
        "samples": len(signal),
        "duration": float(relative_time[-1]),
        "max": int(np.max(signal)),
        "min": int(np.min(signal)),
        "mean": float(np.mean(signal)),
    }

    print("Total Original Packets:", stats["total_packets"])
    print("Total Generated Samples:", stats["samples"])
    print("Total Packets in Signal:", int(np.sum(signal)))
    print("Maximum Packet Count:", stats["max"])
    print("Minimum Packet Count:", stats["min"])
    print("Mean Packet Count: {:.4f}".format(stats["mean"]))
    print("Capture Duration: {:.1f} seconds".format(stats["duration"]))
    print("Signal saved at:", csv_path)

    return {
        "pcap_path": pcap_path,
        "signal": signal.astype(float),
        "time_axis": time_axis.astype(float),
        "sampling_interval": float(sampling_interval),
        "stats": stats,
        "csv_path": csv_path,
    }


def plot_signal(signal, time_axis, first_n=500):

    from . import COLOR_ORANGE, COLOR_TEAL, apply_dark_style, draw_discrete

    apply_dark_style()
    import matplotlib.pyplot as plt

    signal = np.asarray(signal, dtype=float)
    time_axis = np.asarray(time_axis, dtype=float)

    fig, axes = plt.subplots(2, 1, figsize=(7.6, 6.2), constrained_layout=True)

    draw_discrete(axes[0], time_axis, signal, color=COLOR_TEAL,
                  label="Packet rate", marker=True, marker_size=4.6)
    axes[0].set_title("Network Traffic Signal — Full Overview")
    axes[0].set_xlabel("Time (Seconds)")
    axes[0].set_ylabel("Packets per Second")
    axes[0].legend(loc="upper right")

    n = min(first_n, len(signal))
    draw_discrete(axes[1], time_axis[:n], signal[:n], color=COLOR_ORANGE,
                  label="Discrete samples", marker=True, marker_size=6.0)
    axes[1].set_title("First {} Seconds — Discrete Samples".format(n))
    axes[1].set_xlabel("Time (Seconds)")
    axes[1].set_ylabel("Packets per Second")
    axes[1].legend(loc="upper right")

    return fig

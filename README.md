# NetSpectra

### Network traffic analysis through Digital Signal Processing

**NetSpectra** is a Python desktop application that turns recorded network packets into discrete traffic signals and analyzes them using **Digital Signal Processing (DSP)**. It combines packet-to-signal transformation, time- and frequency-domain analysis, moving-average filtering, convolution, recursive systems, and traffic-volume anomaly detection.

The project's central application is investigating suspicious traffic bursts that may indicate DDoS activity. Its DSP operations are also core educational and analytical features—not just export utilities.

> **Scope:** NetSpectra analyzes recorded captures offline. Its DDoS module flags suspicious volume anomalies; it does not confirm malicious intent, establish that attackers are distributed, or block traffic.

## Features

- **Packet-to-signal transformation:** convert `.pcap`, `.pcapng`, and `.cap` packet timestamps into uniformly spaced packet-count samples.
- **Signal visualization:** inspect traffic volume, quiet intervals, and concentrated bursts.
- **Fourier analysis:** examine the mean-centered signal's FFT magnitude and phase.
- **Moving-average filtering:** smooth traffic fluctuations using a finite averaging kernel.
- **Convolution comparison:** compare direct linear convolution with FFT-based convolution.
- **Recursive system analysis:** explore a first-order difference equation applied to network traffic.
- **DDoS-oriented anomaly detection:** identify extreme samples using a baseline-relative threshold and rank cap.
- **Event reporting:** group consecutive flags and assign relative-intensity severity labels.
- **Exports:** save signal data, DSP outputs, event reports, and plots.

## Contents

- [Getting started](#getting-started)
- [PCAPNG packets to signal transformation](#pcapng-packets-to-signal-transformation)
- [DSP operations](#dsp-operations)
- [DDoS detection](#ddos-detection)
- [Using the desktop application](#using-the-desktop-application)
- [Exports](#exports)
- [Project organization](#project-organization)
- [Limitations and interpretation](#limitations-and-interpretation)
- [Responsible use](#responsible-use)

## Getting started

### Requirements

- Python 3.
- A graphical desktop with Tkinter available.
- `numpy`, `pandas`, `matplotlib`, `scapy`, and `customtkinter`.
- A packet capture you are authorized to analyze.

### Installation

```bash
git clone https://github.com/Gamal-Ahmed-Shiha/NetSpectra.git
cd NetSpectra
python -m venv .venv
```

Activate the environment on Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Or on Linux / macOS:

```bash
source .venv/bin/activate
```

Install dependencies and launch the application:

```bash
python -m pip install numpy pandas matplotlib scapy customtkinter
python main.py
```

> Some operating systems require a separate Python/Tk package. A graphical display is required.

## PCAPNG packets to signal transformation

**Implementation:** [`operations/signal_generation.py`](operations/signal_generation.py)

A capture contains packet records with individual arrival timestamps. These arrivals are irregularly spaced: a busy interval may contain many packets, while another contains none.

NetSpectra converts this event stream into a **uniformly sampled traffic-volume sequence** by counting packet arrivals inside fixed-duration time bins. This creates the common input used by the DSP operations and the DDoS detector.

### 1. Extract packet timestamps

Scapy's `PcapReader` reads the capture, and the application collects each packet's timestamp:

```python
with PcapReader(pcap_path) as reader:
    for packet in reader:
        timestamps.append(float(packet.time))
```

Every packet returned by the reader contributes a timestamp. The transformation does not currently filter by protocol, source address, destination address, payload, or packet length.

### 2. Convert absolute timestamps to relative time

The first packet's timestamp becomes the origin:

$$
\tau_i = t_i - t_0
$$

- $t_i$: arrival timestamp of packet $i$.
- $t_0$: timestamp of the first packet read.
- $\tau_i$: elapsed time relative to that first packet.

The resulting time axis starts at zero instead of an absolute capture timestamp.

### 3. Define fixed-duration bins

Let $\Delta t$ be the sampling interval, which defaults to **1.0 second**. The implementation chooses:

$$
N = \max\left(1,\left\lceil\frac{\tau_{\mathrm{last}}}{\Delta t}\right\rceil\right)
$$

It applies `numpy.histogram` over the range from zero to $N\Delta t$.

Each interval produces one sample. Intervals without captured packets produce zero-valued samples. NumPy histogram bins are half-open except for the final bin, which includes its rightmost edge.

> Packet order matters: the implementation uses the first record as the time origin and the last record to determine duration. It assumes chronological packet ordering.

### 4. Construct the discrete signal

$$
x[n] = \#\{\text{packets assigned to bin }n\}
$$

The sample's time coordinate is:

$$
t[n] = n\Delta t
$$

| Signal behavior | Traffic interpretation |
|---|---|
| High sample value | Many packet arrivals in that interval |
| Low sample value | Less captured traffic |
| Zero sample | No captured packets in the interval |
| Sharp peak | A concentrated traffic burst |

This is a **packet-arrival volume signal**, not an electrical waveform or a reconstruction of packet payloads.

### Packet counts versus packet rates

The generated signal stores **packets per bin**. With one-second bins, the numerical values also represent packets per second.

For another bin width, normalization would be needed to express a packet rate:

$$
r[n] = \frac{x[n]}{\Delta t}
$$

The current signal-generation implementation does not apply this division. Some plots and DDoS report fields use packets-per-second terminology, so keep **1.0-second bins** when interpreting those labels literally.

### Sampling interval trade-off

- **Smaller bins:** show finer timing details and brief bursts, but produce a more granular sequence.
- **Larger bins:** aggregate more arrivals into each sample and can hide short bursts inside longer intervals.

The sampling interval defines the temporal resolution of every operation that follows.

### Signal export

The generated sequence is saved to `results/network_signal.csv`:

| Column | Meaning |
|---|---|
| `Time` | Relative start time of the bin |
| `Packet_Count` | Number of packets assigned to the bin |

The operation also reports the original packet count, generated sample count, capture duration, and maximum, minimum, and mean sample values.

## DSP operations

The packet-count signal is the foundation for the project's DSP features. These operations offer complementary views of network traffic: temporal variation, frequency content, smoothing, convolution equivalence, and recursive system behavior.

**Important:** these are individually available analytical operations. The current DDoS detector uses the traffic signal directly; it does not require FFT analysis, filtering, or recursive-system processing first.

### 1. Time-domain inspection

**Input:** the generated traffic signal and its time axis.

Time-domain visualization makes it possible to inspect changes in packet volume, quiet intervals, sudden peaks, and sustained traffic activity. It is the most direct connection between the capture's packet arrivals and the resulting discrete sequence.

The application visualizes the full signal and an initial sample window.

### 2. Fourier / DTFT exploration

**Implementation:** [`operations/fourier.py`](operations/fourier.py)

The Fourier operation subtracts the signal mean, computes an FFT, and centers the frequency representation with `fftshift`.

Mean removal gives:

$$
x_c[n] = x[n] - \bar{x}
$$

The DFT of the centered sequence is:

$$
X[k] = \sum_{n=0}^{N-1} x_c[n]e^{-j2\pi kn/N}
$$

The operation exports:

- **Magnitude:** the strength of each represented frequency component.
- **Phase:** the corresponding phase angle.

Mean subtraction reduces the constant offset so the spectrum emphasizes variations around the average traffic level. A frequency-domain view can help explore repeating variations that are less obvious in the raw time plot.

> The FFT computes discrete samples of the finite sequence's DTFT, not a continuous spectrum at every frequency. A spectral peak alone does not establish an attack.

**Outputs:** `fourier_spectrum.csv` and `fourier.png`.

### 3. Moving-average filtering

**Implementation:** [`operations/filters.py`](operations/filters.py)

The filter constructs an $M$-tap averaging kernel:

$$
h[n] =
\begin{cases}
\frac{1}{M}, & 0 \leq n < M \\
0, & \text{otherwise}
\end{cases}
$$

The filtered output is linear convolution:

$$
y[n] = (x*h)[n]
$$

Equivalently, under zero-valued prehistory:

$$
y[n] = \frac{1}{M}\sum_{m=0}^{M-1}x[n-m]
$$

The implementation performs full linear convolution and retains the first $N$ output samples to match the input length.

**Interpretation:**

- A smaller window preserves more short-term variation.
- A larger window produces stronger smoothing but can flatten brief peaks.
- Initial samples include a boundary transient because the signal before its first sample is treated as zero.

This operation helps inspect broader traffic trends while reducing rapid sample-to-sample fluctuations. It is not automatically applied before DDoS detection.

**Outputs:** `filtered_signal.csv` and `filter.png`.

### 4. Direct versus FFT-based convolution

**Implementation:** [`operations/convolution.py`](operations/convolution.py)

The convolution operation compares two ways to compute the same linear-convolution result.

**Time-domain formulation:**

$$
y[n] = \sum_m x[m]h[n-m]
$$

**Frequency-domain formulation:**

$$
y = \operatorname{IFFT}\left(\operatorname{FFT}(x,L)\operatorname{FFT}(h,L)\right)
$$

For input lengths $N$ and $M$, the operation zero-pads to:

$$
L = N + M - 1
$$

This padding allows FFT multiplication to reproduce the full linear convolution rather than a shorter, wrapped circular-convolution result.

The operation compares the independently computed outputs and reports their numerical difference. Small differences can result from floating-point arithmetic.

**Purpose:** demonstrate the convolution theorem using an actual traffic signal and compare the time- and frequency-domain computations.

**Outputs:** `convolution_comparison.csv` and `convolution.png`.

### 5. Recursive difference equation

**Implementation:** [`operations/systems.py`](operations/systems.py)

The system operation applies:

$$
y[n] = a x[n] + b y[n-1],\qquad y[-1]=0
$$

The default coefficients are:

$$
a=0.5,\qquad b=0.5
$$

- $a$ controls the current input's contribution.
- $b$ controls the previous output's contribution.
- The previous output gives the system memory.

Unlike the finite moving-average kernel, this recursive system can carry the effect of previous samples forward through feedback. Its behavior depends on the selected coefficients; it should not be interpreted as a validated attack detector.

**Outputs:** `difference_output.csv` and `system.png`.

### How DSP supports traffic analysis

| Operation | Main analytical question |
|---|---|
| Time-domain view | When does traffic rise, fall, or burst? |
| Fourier analysis | What frequency components appear in traffic variations? |
| Moving average | What broader trend remains after smoothing? |
| Convolution comparison | Do direct and FFT-based computations agree? |
| Recursive system | How does feedback change the signal's response? |
| DDoS-oriented detector | Which extreme samples satisfy the rank and baseline rules? |

These views complement each other, but the current implementation does not combine them into a single automated DSP-based classification pipeline.

## DDoS detection

**Implementation:** [`operations/ddos_detection.py`](operations/ddos_detection.py)

NetSpectra implements a **rank-based, baseline-relative traffic-volume anomaly detector**. It identifies unusually large packet-count samples and groups consecutive flags into suspicious events.

A sample must satisfy both rules:

1. Be among the highest-volume samples allowed by the rank cap.
2. Reach the configured multiple of the baseline.

### 1. Estimate the baseline

The initial normal-traffic baseline is the full signal's median:

$$
B = \operatorname{median}(x)
$$

If the median is nonpositive, the implementation falls back to the mean. If the resulting baseline is still nonpositive, it uses an infinite threshold, so an all-zero signal is not flagged.

The median is less sensitive than the mean to isolated large peaks. However, this baseline comes from the entire capture—not an independently verified clean period.

### 2. Set the threshold

$$
T = E B
$$

The exaggeration factor $E$ defaults to **5.0**. A candidate must satisfy:

$$
x[n] \geq E B
$$

A higher factor requires a more extreme burst relative to the baseline; a lower factor admits less-extreme peaks.

### 3. Select top-ranked candidates

For $N$ samples and top percentage $p$:

$$
K = \max\left(1,\left\lceil N\frac{p}{100}\right\rceil\right)
$$

The default $p$ is **1.0%**. The detector selects the $K$ largest sample values. Ties are ordered by sample index, with earlier samples selected first.

> This is a candidate-count cap, not merely a percentile threshold. Rounding and the minimum of one candidate can make the selected fraction exceed the requested percentage for short captures.

### 4. Apply both conditions

Let $\mathcal{C}$ be the selected candidate indices:

$$
\operatorname{flag}(n) = \left(n\in\mathcal{C}\right)\land\left(x[n]\geq E B\right)
$$

Crossing the threshold alone is insufficient. A sample must also belong to the top-ranked candidate set.

### 5. Group consecutive flags

Flagged indices are sorted chronologically. Adjacent flags form one event; an unflagged sample separates events.

Each event includes:

- First and last flagged sample indices.
- Start and end time coordinates.
- Consecutive flagged sample count.
- Peak sample value.
- Total packets across flagged bins.
- Peak-to-baseline ratio.
- Severity label.

Events are reported in descending peak order.

### 6. Assign severity

$$
R = \frac{\text{event peak}}{B}
$$

| Peak-to-baseline ratio | Severity |
|---|---|
| $R\geq8$ | `CRITICAL` |
| $4\leq R<8$ | `HIGH` |
| $R<4$ | `MEDIUM` |

These labels describe relative traffic intensity, not verified impact or certainty that an attack occurred. The default exaggeration factor admits `HIGH` and `CRITICAL` events; lower settings can admit `MEDIUM` events.

### GUI parameters

| Parameter | Default | GUI range / requirement | Purpose |
|---|---|---|---|
| Sampling interval | 1.0 s | Positive user-entered interval | Sets bin width |
| Top percentage | 1.0% | 0.1–5.0% | Caps candidate samples |
| Exaggeration factor | 5.0 | 2.0–10.0 | Sets baseline multiplier |

Increasing the top percentage allows more samples to be considered. Reducing the exaggeration factor relaxes the threshold. Neither change verifies malicious behavior.

### Visualization and event report

The detection plot shows the traffic signal, threshold, flagged peak markers, and shaded event regions.

When events exist, `results/ddos_events.csv` contains:

| Column | Meaning |
|---|---|
| `Event_ID` | Identifier in descending peak order |
| `Start_Time_s` | Start coordinate of the first flagged bin |
| `End_Time_s` | Start coordinate of the last flagged bin |
| `Duration_s` | Flagged sample count; seconds only for one-second bins |
| `Peak_Packets_Per_Second` | Peak bin count; packets/s only for one-second bins |
| `Total_Packets` | Packet count summed across event bins |
| `Ratio_To_Normal` | Peak divided by baseline |
| `Severity` | Relative-intensity label |

The end coordinate is not the end of the final bin. The current duration calculation counts samples rather than multiplying by the sampling interval.

If no events are detected, a new event CSV is not written; an older `ddos_events.csv` can remain from a previous run.

## Using the desktop application

### Capture loading and signal generation

1. Launch `main.py`.
2. Select **Upload PCAP** and choose a capture.
3. The application copies it into `pcaps/` and automatically runs **Signal Generation**.
4. Inspect the traffic signal and summary statistics.

On startup, the application also loads the newest capture by modification time from `pcaps/`, when available, and generates its signal.

### DSP exploration

Use the operation controls to explore Fourier analysis, moving-average filtering, convolution comparison, and the recursive difference equation. Review each operation's plots and corresponding CSV output.

These operations are available for studying the traffic sequence; they are not prerequisites for running the detector.

### DDoS-oriented analysis

1. Keep the sampling interval at **1.0 second** for directly interpretable DDoS time and rate labels.
2. Select **DDoS Detection**.
3. Adjust **Top % of seconds (rank cap)** and **Flag above (× median)** when needed.
4. Click **Detect Attacks**.
5. Review flagged peaks, grouped events, and exported results.

Treat flagged events as candidates for further investigation, not final incident verdicts.

## Exports

CSV files are written to `results/`; plot images are written to `results/plots/`.

| Operation | CSV output | Plot output |
|---|---|---|
| Signal Generation | `network_signal.csv` | `signal.png` |
| Fourier / DTFT | `fourier_spectrum.csv` | `fourier.png` |
| Moving Average Filter | `filtered_signal.csv` | `filter.png` |
| Convolution comparison | `convolution_comparison.csv` | `convolution.png` |
| Difference Equation | `difference_output.csv` | `system.png` |
| DDoS Detection | `ddos_events.csv`, when events exist | `ddos.png` |

Output filenames are reused. Preserve results you need before analyzing another capture or changing parameters.

## Project organization

| Location | Role |
|---|---|
| `main.py` | Desktop interface, loading workflow, controls, and rendering |
| `operations/signal_generation.py` | Timestamp extraction and histogram-based signal generation |
| `operations/fourier.py` | FFT magnitude and phase analysis |
| `operations/filters.py` | Moving-average filtering |
| `operations/convolution.py` | Direct versus FFT-based convolution |
| `operations/systems.py` | First-order recursive system |
| `operations/ddos_detection.py` | Baseline, rank selection, events, and severity |
| `operations/__init__.py` | Shared directories, plotting style, and helpers |
| `pcaps/` | Captures used by the application |
| `results/` | Generated CSV outputs |
| `results/plots/` | Exported PNG plots |

## Limitations and interpretation

- **An anomaly is not a confirmed DDoS attack.** Legitimate bursts can be flagged; low-rate and application-layer attacks can be missed.
- **Distribution is not established.** The detector does not inspect source diversity, destination targeting, connection state, or protocol behavior.
- **DSP views are not attack proof.** Frequency peaks, smoothing behavior, and recursive-system outputs require interpretation.
- **The detector is not a combined DSP classifier.** It operates on the traffic signal directly, rather than automatically combining FFT, filter, and system outputs.
- **The rank cap limits coverage.** Sustained high traffic can be partially flagged or split into smaller events.
- **The baseline is capture-wide.** Abnormal traffic dominating a capture can distort it; a zero median triggers the mean fallback.
- **Prefer one-second bins for current DDoS labels.** Other widths require care with units, duration, and shading; event shading currently extends the last flagged coordinate by one second.
- **Packet order matters.** Unsorted timestamps can produce misleading histogram coverage and duration.
- **Large captures consume memory.** Packet objects are read incrementally, but timestamps and the signal remain in memory.
- **Detection accuracy is not claimed.** Precision, recall, and false-positive rates require evaluation against labeled captures.

## Responsible use

Analyze only traffic you are authorized to inspect. Captures can contain sensitive information: review and sanitize them before publishing them in a public repository.

NetSpectra is intended for defensive traffic analysis, DSP exploration, and education.

---

**From packet arrivals to discrete signals. From DSP exploration to suspicious-traffic investigation.**

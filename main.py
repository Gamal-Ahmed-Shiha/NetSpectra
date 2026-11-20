import os
import queue
import shutil
import threading
import traceback
from contextlib import redirect_stdout
from io import StringIO

import matplotlib
matplotlib.use("Agg")  

import numpy as np

import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, ttk

from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from operations import PCAPS_DIR, apply_dark_style, save_figure
from operations import signal_generation as sg
from operations import fourier as fr
from operations import filters as fl
from operations import convolution as cv
from operations import systems as sy
from operations import ddos_detection as dd


BG         = "#0a0f16"  
SIDEBAR    = "#0d1521"   
CARD       = "#101a29"   
CARD_DARK  = "#0c1420"   
FIG_BG     = "#0d1520"   
BORDER     = "#1d2b3d"
TEXT       = "#e8eef6"
MUTED      = "#8fa0b3"
TEAL       = "#00e5cc"
TEAL_HOVER = "#2ff0d8"
TEAL_DIM   = "#0d4a44"
TEAL_TEXT  = "#06231f"

RED    = "#ff5c5d"
ORANGE = "#ffb454"
GREEN  = "#39d98a"

FONT       = ("Segoe UI", 13)
FONT_SM    = ("Segoe UI", 11)
FONT_TINY  = ("Segoe UI", 10)
FONT_BOLD  = ("Segoe UI", 13, "bold")
FONT_H2    = ("Segoe UI", 17, "bold")
FONT_BRAND = ("Segoe UI", 21, "bold")
FONT_VALUE = ("Segoe UI", 14, "bold")
FONT_MONO  = ("Consolas", 10)


OPS = [
    ("signal",  "Signal Generation",
     "Turns the uploaded PCAP into the discrete packets-per-second signal "
     "and exports network_signal.csv.",
     "Generate Signal"),
    ("fourier", "Fourier · DTFT",
     "Computes the DTFT of the packet-rate signal via FFT after removing "
     "the DC component (the mean), then plots the magnitude and phase spectra.",
     "Compute DTFT"),
    ("filter",  "Moving Average Filter",
     "Smooths the traffic with an M-tap moving average kernel using linear "
     "convolution — fast fluctuations disappear, the trend stays.",
     "Apply Filter"),
    ("conv",    "Convolution ×2",
     "Proves that time-domain convolution equals frequency-domain "
     "multiplication (FFT with zero padding to L = N + M − 1). The overlap "
     "is the convolution theorem at work; the residual ~1e-16 relative "
     "difference is float64 round-off, shown on a log scale.",
     "Compare Methods"),
    ("system",  "Difference Equation",
     "Applies the first-order recursive system y[n] = a·x[n] + b·y[n-1] "
     "with initial condition y[-1] = 0 to the traffic signal.",
     "Run System"),
    ("ddos",    "DDoS Detection",
     "RANK-BASED flags: only the highest Top % of seconds of the whole "
     "capture are even eligible, and an eligible second is flagged only "
     "when its rate is a gross exaggeration of the normal level "
     "(median). No statistical line can mass-flag ordinary traffic — "
     "just a handful of genuinely suspicious points; consecutive flagged "
     "seconds form one event; severity = peak / normal: ≥ 8 → CRITICAL, "
     "≥ 4 → HIGH.",
     "Detect Attacks"),
]
OP_TITLES = {op_id: title for op_id, title, _d, _r in OPS}
OP_DESCS = {op_id: desc for op_id, _t, desc, _r in OPS}
OP_RUNS = {op_id: run for op_id, _t, _d, run in OPS}

TABLE_COLS = ("#", "Start (s)", "End (s)", "Dur (s)", "Peak pkt/s",
              "Total pkts", "Ratio", "Severity")


class NetworkDSPApp(ctk.CTk):
    """Main window: sidebar navigation + upload bar + controls + plots."""

    def __init__(self):
        super().__init__(fg_color=BG)

        ctk.set_appearance_mode("dark")

        self.title("Network DSP — Network Traffic Signal Analysis")
        self.geometry("1360x860")
        self.minsize(1180, 740)

      
        self.current_op = "signal"
        self.pcap_path = None
        self.signal = None
        self.time_axis = None
        self.sampling_interval = 1.0
        self.last_kernel = None
        self.busy = False
        self._ui_queue = queue.Queue()

        self._style_treeview()
        self._build_sidebar()
        self._build_main()
        self._build_control_panels()
        self.select_op("signal")
        self.after(80, self._drain_queue)

        self.log("Network DSP ready.", "hd")
        self.log("1) Click Upload PCAP — the file is copied into pcaps/",
                 "muted")
        self.log("   (a capture already inside pcaps/ is loaded automatically)",
                 "muted")
        self.log("2) Signal Generation runs automatically", "muted")
        self.log("3) Pick an operation on the left and press its Run button",
                 "muted")
        # Restore the capture from the previous session (if any) and run the
        # analysis, so the user never has to re-upload the same file twice.
        self.after(300, self._autoload_previous_capture)

    # ================================================================ UI

    def _style_treeview(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("DSP.Treeview", background=CARD_DARK,
                        fieldbackground=CARD_DARK, foreground=TEXT,
                        rowheight=28, borderwidth=0, font=FONT_SM)
        style.configure("DSP.Treeview.Heading", background=CARD,
                        foreground=TEAL, font=FONT_SM, borderwidth=0,
                        relief="flat")
        style.map("DSP.Treeview",
                  background=[("selected", TEAL_DIM)],
                  foreground=[("selected", "#eafffb")])
        style.map("DSP.Treeview.Heading",
                  background=[("active", CARD)])

    # ----------------------------------------------------------- sidebar

    def _build_sidebar(self):
        side = ctk.CTkFrame(self, width=250, fg_color=SIDEBAR, corner_radius=0)
        side.grid(row=0, column=0, sticky="nsw")
        side.grid_propagate(False)
        side.pack_propagate(False)

        ctk.CTkLabel(side, text="NETWORK DSP", font=FONT_BRAND,
                     text_color=TEAL).pack(anchor="w", padx=24, pady=(28, 0))
        ctk.CTkLabel(side, text="Network Traffic · Signal Analysis",
                     font=FONT_TINY, text_color=MUTED).pack(anchor="w", padx=24)

        ctk.CTkFrame(side, height=2, width=44, fg_color=TEAL,
                     corner_radius=2).pack(anchor="w", padx=24, pady=(12, 8))

        ctk.CTkLabel(side, text="OPERATIONS", font=FONT_TINY,
                     text_color=MUTED).pack(anchor="w", padx=24, pady=(14, 6))

        self.nav_buttons = {}
        for op_id, title, _desc, _run in OPS:
            btn = ctk.CTkButton(
                side, text=title, anchor="w", height=40, corner_radius=8,
                fg_color="transparent", hover_color=CARD,
                text_color=MUTED, font=FONT,
                command=lambda oid=op_id: self.select_op(oid),
            )
            btn.pack(fill="x", padx=16, pady=2)
            self.nav_buttons[op_id] = btn

        # status card pinned to the bottom
        status = ctk.CTkFrame(side, fg_color=CARD, corner_radius=10,
                              border_width=1, border_color=BORDER)
        status.pack(side="bottom", fill="x", padx=16, pady=16)
        row = ctk.CTkFrame(status, fg_color="transparent")
        row.pack(fill="x", padx=12, pady=10)
        self.status_dot = ctk.CTkLabel(row, text="●", font=FONT,
                                       text_color=TEAL, width=18)
        self.status_dot.pack(side="left")
        self.status_label = ctk.CTkLabel(row, text="Ready — upload a PCAP",
                                         font=FONT_SM, text_color=TEXT,
                                         anchor="w")
        self.status_label.pack(side="left", padx=(6, 0), fill="x", expand=True)

    # -------------------------------------------------------------- main

    def _build_main(self):
        main = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)
        main.grid(row=0, column=1, sticky="nsew")
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(1, weight=1)

        # ---------------------------------------------------------- topbar
        topbar = ctk.CTkFrame(main, height=68, fg_color=SIDEBAR, corner_radius=0)
        topbar.grid(row=0, column=0, sticky="ew")
        topbar.grid_propagate(False)

        self.upload_btn = ctk.CTkButton(
            topbar, text="Upload PCAP", width=160, height=42, corner_radius=10,
            fg_color=TEAL, hover_color=TEAL_HOVER, text_color=TEAL_TEXT,
            font=FONT_BOLD, command=self.upload_pcap,
        )
        self.upload_btn.pack(side="left", padx=(20, 14), pady=13)

        self.file_chip = ctk.CTkLabel(topbar, text="No capture loaded",
                                      font=FONT_SM, text_color=MUTED)
        self.file_chip.pack(side="left", padx=4)

        ctk.CTkLabel(topbar, text="Exports →  results/  (CSV + PNG)",
                     font=FONT_TINY, text_color=MUTED).pack(side="right",
                                                            padx=20)

        # ------------------------------------------------------------ body
        body = ctk.CTkFrame(main, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew")
        body.grid_columnconfigure(0, weight=0, minsize=312)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        # ---- left column: operation header + controls + console
        left = ctk.CTkFrame(body, fg_color="transparent")
        left.grid(row=0, column=0, sticky="ns", padx=(14, 8), pady=12)

        header = ctk.CTkFrame(left, fg_color=CARD, corner_radius=12,
                              border_width=1, border_color=BORDER)
        header.pack(fill="x")
        self.op_title = ctk.CTkLabel(header, text="", font=FONT_H2,
                                     text_color=TEAL, anchor="w",
                                     wraplength=260, justify="left")
        self.op_title.pack(anchor="w", padx=16, pady=(14, 2))
        self.op_desc = ctk.CTkLabel(header, text="", font=FONT_TINY,
                                    text_color=MUTED, anchor="w",
                                    wraplength=260, justify="left")
        self.op_desc.pack(anchor="w", padx=16, pady=(0, 6))
        ctk.CTkFrame(header, height=3, width=44, fg_color=TEAL,
                     corner_radius=2).pack(anchor="w", padx=16, pady=(0, 14))

        controls_holder = ctk.CTkFrame(left, fg_color=CARD, corner_radius=12,
                                       border_width=1, border_color=BORDER)
        controls_holder.pack(fill="x", pady=10)
        self.controls_inner = ctk.CTkFrame(controls_holder,
                                           fg_color="transparent")
        self.controls_inner.pack(fill="both", expand=True, padx=6, pady=(6, 0))

        self.run_btn = ctk.CTkButton(
            controls_holder, text="Run", height=42, corner_radius=10,
            fg_color=TEAL, hover_color=TEAL_HOVER, text_color=TEAL_TEXT,
            font=FONT_BOLD, command=self.run_current,
        )
        self.run_btn.pack(fill="x", padx=14, pady=(10, 14))

        console_card = ctk.CTkFrame(left, fg_color=CARD, corner_radius=12,
                                    border_width=1, border_color=BORDER)
        console_card.pack(fill="both", expand=True, pady=(10, 0))
        ctk.CTkLabel(console_card, text="CONSOLE", font=FONT_TINY,
                     text_color=MUTED).pack(anchor="w", padx=16, pady=(12, 4))
        self.console = ctk.CTkTextbox(
            console_card, fg_color=BG, text_color="#9fd8cf", font=FONT_MONO,
            wrap="word",
        )
        self.console.pack(fill="both", expand=True, padx=10, pady=(0, 12))
        for tag, color in (("err", RED), ("ok", GREEN), ("muted", MUTED),
                           ("hd", TEAL), ("body", "#9fd8cf")):
            try:
                self.console.tag_config(tag, foreground=color)
            except Exception:
                pass

        # ---- right column: stats chips + figure + events table
        right = ctk.CTkFrame(body, fg_color="transparent")
        right.grid(row=0, column=1, sticky="nsew", padx=(0, 14), pady=12)
        right.grid_rowconfigure(1, weight=1)
        right.grid_columnconfigure(0, weight=1)

        self.stats_row = ctk.CTkFrame(right, fg_color="transparent")
        self.stats_row.grid(row=0, column=0, sticky="ew")

        plot_card = ctk.CTkFrame(right, fg_color=FIG_BG, corner_radius=12,
                                 border_width=1, border_color=BORDER)
        plot_card.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        self.plot_caption = ctk.CTkLabel(plot_card, text="", font=FONT_TINY,
                                         text_color=MUTED, anchor="w")
        self.plot_caption.pack(anchor="w", padx=14, pady=(10, 0))
        self.plot_inner = ctk.CTkFrame(plot_card, fg_color=FIG_BG)
        self.plot_inner.pack(fill="both", expand=True, padx=8, pady=(2, 8))
        self.plot_placeholder = ctk.CTkLabel(
            self.plot_inner,
            text="Upload a PCAP capture and run an operation\n"
                 "to see its figure here.",
            font=FONT, text_color=MUTED,
        )
        self.plot_placeholder.pack(expand=True)
        self._canvas = None

        # events table (DDoS operation)
        self.table_card = ctk.CTkFrame(right, fg_color=CARD, corner_radius=12,
                                       border_width=1, border_color=BORDER)
        self._table_built = False

    # ---------------------------------------------------- control panels

    def _panel(self):
        return ctk.CTkFrame(self.controls_inner, fg_color="transparent")

    @staticmethod
    def _caption(panel, text):
        ctk.CTkLabel(panel, text=text, font=FONT_TINY, text_color=MUTED,
                     anchor="w", wraplength=250, justify="left"
                     ).pack(fill="x", padx=12, pady=(8, 2))

    def _build_control_panels(self):
        self.panels = {}

        # ------------------------------------------------ signal
        p = self._panel()
        ctk.CTkLabel(p, text="Sampling Interval (seconds)", font=FONT_SM,
                     text_color=TEXT, anchor="w").pack(fill="x", padx=12,
                                                       pady=(10, 2))
        self.ent_interval = ctk.CTkEntry(p, width=120, height=34,
                                         fg_color=CARD_DARK,
                                         border_color=BORDER, text_color=TEXT)
        self.ent_interval.insert(0, "1.0")
        self.ent_interval.pack(anchor="w", padx=12, pady=4)
        self._caption(p, "Each bin gathers the packets of one interval into "
                         "a single discrete sample x[n]. Re-runs the "
                         "analysis of the uploaded capture.")
        self.panels["signal"] = p

        # ------------------------------------------------ fourier
        p = self._panel()
        self._caption(p, "The mean (DC component) is subtracted before the "
                         "FFT, then the zero-frequency bin is shifted to "
                         "the center: the spectrum spans −Fs/2 … +Fs/2.")
        self._caption(p, "Magnitude: how much of each frequency exists in "
                         "the traffic.  Phase: the angle of each frequency "
                         "component in radians.")
        self.panels["fourier"] = p

        # ------------------------------------------------ filter
        p = self._panel()
        row = ctk.CTkFrame(p, fg_color="transparent")
        row.pack(fill="x", padx=12, pady=(10, 0))
        ctk.CTkLabel(row, text="Window Size M (taps)", font=FONT_SM,
                     text_color=TEXT, anchor="w").pack(side="left")
        self.lbl_m = ctk.CTkLabel(row, text="M = 5", font=FONT_BOLD,
                                  text_color=TEAL)
        self.lbl_m.pack(side="right")
        self.sld_m = ctk.CTkSlider(
            p, from_=3, to=25, number_of_steps=11,
            fg_color=CARD_DARK, progress_color=TEAL, button_color=TEAL,
            button_hover_color=TEAL_HOVER,
            command=lambda v: self.lbl_m.configure(text="M = {0:g}".format(v)))
        self.sld_m.set(5)
        self.sld_m.pack(fill="x", padx=12, pady=(6, 2))
        self._caption(p, "Kernel h[n] = 1/M · ones(M). The same kernel is "
                         "reused later by the Convolution operation.")
        self.panels["filter"] = p

        # ------------------------------------------------ convolution
        p = self._panel()
        self._caption(p, "Runs the moving average kernel (M taken from the "
                         "Moving Average Filter panel) through both methods:")
        self._caption(p, "1. Direct convolution in the time domain.")
        self._caption(p, "2. Zero-padded FFT multiplication with "
                         "L = N + M − 1, then inverse FFT.")
        self._caption(p, "The two curves come from two completely different "
                         "computations — their overlap is the convolution "
                         "theorem working, not one curve copying the other.")
        self._caption(p, "The residual difference is float64 round-off: "
                         "relative error ≈ 1e-16 (the last binary digit). "
                         "The lower panel shows it on a log scale next to "
                         "the float64 precision limit.")
        self.panels["conv"] = p

        # ------------------------------------------------ system
        p = self._panel()
        for name, attr in (("Coefficient a", "a"), ("Coefficient b", "b")):
            row = ctk.CTkFrame(p, fg_color="transparent")
            row.pack(fill="x", padx=12, pady=(8, 0))
            ctk.CTkLabel(row, text=name, font=FONT_SM, text_color=TEXT,
                         anchor="w").pack(side="left")
            lbl = ctk.CTkLabel(row, text="0.50", font=FONT_BOLD,
                               text_color=TEAL)
            lbl.pack(side="right")
            sld = ctk.CTkSlider(
                p, from_=0.05, to=1.0, number_of_steps=19,
                fg_color=CARD_DARK, progress_color=TEAL, button_color=TEAL,
                button_hover_color=TEAL_HOVER,
                command=lambda v, l=lbl: l.configure(
                    text="{0:.2f}".format(v)))
            sld.set(0.5)
            sld.pack(fill="x", padx=12, pady=(4, 2))
            setattr(self, "sld_" + attr, sld)
        self._caption(p, "y[n] = a·x[n] + b·y[n-1]   with   y[-1] = 0. "
                         "With a = b the system behaves like an exponential "
                         "smoother (IIR low-pass).")
        self.panels["system"] = p

        # ------------------------------------------------ ddos
        p = self._panel()
        row = ctk.CTkFrame(p, fg_color="transparent")
        row.pack(fill="x", padx=12, pady=(10, 0))
        ctk.CTkLabel(row, text="Top % of seconds (rank cap)", font=FONT_SM,
                     text_color=TEXT, anchor="w").pack(side="left")
        self.lbl_top = ctk.CTkLabel(row, text="1.00 %", font=FONT_BOLD,
                                    text_color=TEAL)
        self.lbl_top.pack(side="right")
        self.sld_top = ctk.CTkSlider(
            p, from_=0.1, to=5.0, number_of_steps=49,
            fg_color=CARD_DARK, progress_color=TEAL, button_color=TEAL,
            button_hover_color=TEAL_HOVER,
            command=lambda v: self.lbl_top.configure(
                text="{0:.2f} %".format(v)))
        self.sld_top.set(1.0)
        self.sld_top.pack(fill="x", padx=12, pady=(6, 2))

        row = ctk.CTkFrame(p, fg_color="transparent")
        row.pack(fill="x", padx=12, pady=(8, 0))
        ctk.CTkLabel(row, text="Flag above (× median)", font=FONT_SM,
                     text_color=TEXT, anchor="w").pack(side="left")
        self.lbl_exag = ctk.CTkLabel(row, text="5.0 ×", font=FONT_BOLD,
                                     text_color=TEAL)
        self.lbl_exag.pack(side="right")
        self.sld_exag = ctk.CTkSlider(
            p, from_=2.0, to=10.0, number_of_steps=16,
            fg_color=CARD_DARK, progress_color=TEAL, button_color=TEAL,
            button_hover_color=TEAL_HOVER,
            command=lambda v: self.lbl_exag.configure(
                text="{0:.1f} ×".format(v)))
        self.sld_exag.set(5.0)
        self.sld_exag.pack(fill="x", padx=12, pady=(6, 2))

        self._caption(p, "Rank-based flags: only the highest Top % of "
                         "seconds of the whole capture are even eligible, "
                         "and an eligible second is flagged only when its "
                         "rate is ≥ exaggeration × median. No statistical "
                         "line can mass-flag ordinary traffic — at most a "
                         "handful of genuinely extreme points are ever "
                         "flagged.")
        self._caption(p, "Severity from peak / normal: ≥ 8 → CRITICAL · "
                         "≥ 4 → HIGH · else MEDIUM. Events are exported to "
                         "ddos_events.csv.")
        self.panels["ddos"] = p

        for panel in self.panels.values():
            panel.grid(row=0, column=0, sticky="nsew")
            panel.grid_remove()

    # --------------------------------------------------------- navigation

    def select_op(self, op_id):
        self.current_op = op_id
        for oid, btn in self.nav_buttons.items():
            active = oid == op_id
            btn.configure(
                fg_color=TEAL_DIM if active else "transparent",
                hover_color=TEAL_DIM if active else CARD,
                text_color=TEAL if active else MUTED,
            )
        for oid, panel in self.panels.items():
            if oid == op_id:
                panel.grid()
            else:
                panel.grid_remove()

        self.op_title.configure(text=OP_TITLES[op_id])
        self.op_desc.configure(text=OP_DESCS[op_id])
        self.run_btn.configure(text=OP_RUNS[op_id])
        self._hide_table()

    # ============================================================ actions

    def _autoload_previous_capture(self):
        """Finds the newest capture inside the pcaps/ folder (left there by a
        previous upload or dropped in manually) and restores the session:
        the file chip is updated and Signal Generation runs automatically."""
        if self.pcap_path is not None or self.busy:
            return
        candidates = []
        try:
            names = os.listdir(PCAPS_DIR)
        except OSError:
            names = []
        for name in names:
            if name.lower().endswith((".pcap", ".pcapng", ".cap")):
                path = os.path.join(PCAPS_DIR, name)
                if os.path.isfile(path):
                    candidates.append((os.path.getmtime(path), path))
        if not candidates:
            return
        _mtime, path = max(candidates)
        self.pcap_path = path
        name = os.path.basename(path)
        size_mb = os.path.getsize(path) / (1024 * 1024)
        self.file_chip.configure(
            text="{0}  ·  {1:.2f} MB".format(name, size_mb))
        self.log("Found capture in pcaps/: {0} ({1:.2f} MB) — loading "
                 "it …".format(name, size_mb), "ok")
        self.run_current()

    def upload_pcap(self):
        if self.busy:
            return
        path = filedialog.askopenfilename(
            title="Select a PCAP capture",
            filetypes=[("PCAP files", "*.pcap *.pcapng *.cap"),
                       ("All files", "*.*")],
        )
        if not path:
            return
        dest = os.path.join(PCAPS_DIR, os.path.basename(path))
        try:
            if os.path.abspath(path) != os.path.abspath(dest):
                shutil.copy2(path, dest)
        except shutil.SameFileError:
            dest = path
        self.pcap_path = dest
        name = os.path.basename(dest)
        size_mb = os.path.getsize(dest) / (1024 * 1024)
        self.file_chip.configure(
            text="{0}  ·  {1:.2f} MB".format(name, size_mb))
        self.log("PCAP loaded: {0} ({1:.2f} MB) — copied into pcaps/".format(
            name, size_mb), "ok")
        self.select_op("signal")
        self.run_current()

    def run_current(self):
        if self.busy:
            return
        op = self.current_op
        if not self.pcap_path or not os.path.isfile(self.pcap_path):
            # Friendly guard — this used to crash inside rdpcap(None)
            self.log("No PCAP loaded — click Upload PCAP first (the file is "
                     "copied into the pcaps/ folder).", "err")
            self.set_status("No capture — upload a PCAP", RED)
            return
        if op != "signal" and self.signal is None:
            self.log("No signal available — run Signal Generation first.",
                     "err")
            self.set_status("No signal — run Signal Generation", ORANGE)
            return
        try:
            params = self._collect_params(op)   # widgets are read HERE,
        except Exception as exc:                # in the main thread only
            self.log("ERROR: " + str(exc), "err")
            return
        self._set_busy(True)
        title = OP_TITLES[op]
        self.set_status("Running {0} …".format(title), ORANGE)
        self.log("── {0} ──".format(title), "hd")
        threading.Thread(target=self._worker, args=(op, params),
                         daemon=True).start()

    def _collect_params(self, op):
        """Reads the widgets of the current operation in the MAIN thread and
        validates them before the worker starts."""
        params = {}
        if op == "signal":
            raw = str(self.ent_interval.get()).strip() or "1.0"
            interval = float(raw)
            if interval <= 0:
                raise ValueError("Sampling interval must be positive.")
            params["interval"] = interval
        elif op == "filter":
            params["m"] = int(round(float(self.sld_m.get())))
        elif op == "conv":
            params["m_fallback"] = int(round(float(self.sld_m.get())))
        elif op == "system":
            params["a"] = float(self.sld_a.get())
            params["b"] = float(self.sld_b.get())
        elif op == "ddos":
            params["top_pct"] = float(self.sld_top.get())
            params["exaggeration"] = float(self.sld_exag.get())
        return params

    # ------------------------------------------------------- worker thread

    def _worker(self, op, params):
        buf = StringIO()
        try:
            with redirect_stdout(buf):
                payload = self._compute(op, params)
            self._ui_queue.put((self._finish, (op, payload, buf.getvalue())))
        except Exception:
            err = traceback.format_exc(limit=3)
            self._ui_queue.put((self._fail, (buf.getvalue(), err)))

    def _drain_queue(self):
        try:
            while True:
                fn, args = self._ui_queue.get_nowait()
                fn(*args)
        except queue.Empty:
            pass
        self.after(80, self._drain_queue)

    # ------------------------------------------------------- computation
    # _compute runs inside the worker thread: heavy work only, no widgets.

    def _compute(self, op, params):
        if op == "signal":
            res = sg.run(self.pcap_path,
                         sampling_interval=params["interval"])
            self.signal = res["signal"]
            self.time_axis = res["time_axis"]
            self.sampling_interval = params["interval"]
            st = res["stats"]

            self._ui_queue.put((self._update_file_chip, (st,)))
            fig = sg.plot_signal(self.signal, self.time_axis)
            return {
                "stats": [
                    ("Total Packets", "{:,}".format(st["total_packets"])),
                    ("Samples", "{:,}".format(st["samples"])),
                    ("Duration", "{:,.0f} s".format(st["duration"])),
                    ("Max Rate", "{:,} pkt/s".format(st["max"])),
                    ("Mean Rate", "{:.2f}".format(st["mean"])),
                ],
                "fig": fig,
                "caption": "Exported: network_signal.csv  ·  plots/signal.png",
            }

        if op == "fourier":
            res = fr.run(self.signal, ts=self.sampling_interval)
            fig = fr.plot_spectrum(res)
            return {
                "stats": [
                    ("Length N", "{:,}".format(res["N"])),
                    ("Sampling Fs", "{:g} Hz".format(res["fs"])),
                    ("Resolution", "{:.3g} Hz".format(res["resolution"])),
                    ("DC Mean", "{:.2f}".format(res["mean"])),
                ],
                "fig": fig,
                "caption": "Exported: fourier_spectrum.csv  ·  "
                           "plots/fourier.png",
            }

        if op == "filter":
            m = params["m"]
            res = fl.run(self.signal, window_size=m,
                         time_axis=self.time_axis)
            self.last_kernel = res["h"]
            fig = fl.plot_filter_comparison(self.signal,
                                            res["filtered_signal"],
                                            self.time_axis)
            return {
                "stats": [
                    ("Window M", str(m)),
                    ("Kernel", "1/M each"),
                    ("Mean (in)",
                     "{:.2f}".format(float(np.mean(self.signal)))),
                    ("Mean (out)",
                     "{:.2f}".format(float(np.mean(res["filtered_signal"])))),
                ],
                "fig": fig,
                "caption": "Exported: filtered_signal.csv  ·  "
                           "plots/filter.png",
            }

        if op == "conv":
            if self.last_kernel is None:
                m = max(params["m_fallback"], 1)
                self.last_kernel = np.ones(m) / m
            res = cv.run(self.signal, self.last_kernel)
            fig = cv.plot_convolution_comparison(
                res["y_time"], res["y_freq"], eps_scaled=res["eps_scaled"])
            return {
                "stats": [
                    ("Signal N", "{:,}".format(res["N"])),
                    ("Kernel M", str(res["M"])),
                    ("FFT Length L", "{:,}".format(res["L"])),
                    ("Max Error", "{:.2e}".format(res["max_error"])),
                    ("Relative Error", "{:.1e}".format(res["rel_error"])),
                ],
                "fig": fig,
                "caption": "Exported: convolution_comparison.csv  ·  "
                           "plots/convolution.png",
            }

        if op == "system":
            a, b = params["a"], params["b"]
            res = sy.run(self.signal, a=a, b=b, time_axis=self.time_axis)
            fig = sy.plot_system_comparison(self.signal,
                                            res["difference_output"],
                                            self.time_axis)
            return {
                "stats": [
                    ("a", "{:.2f}".format(a)),
                    ("b", "{:.2f}".format(b)),
                    ("Output Mean", "{:.2f}".format(float(
                        np.mean(res["difference_output"])))),
                    ("Max Output", "{:.2f}".format(float(
                        np.max(res["difference_output"])))),
                ],
                "fig": fig,
                "caption": "Exported: difference_output.csv  ·  "
                           "plots/system.png",
            }

        if op == "ddos":
            out = dd.run(self.signal, time_axis=self.time_axis,
                         top_pct=params["top_pct"],
                         exaggeration=params["exaggeration"])
            fig = dd.plot_detection(self.signal, out,
                                    time_axis=self.time_axis)

            MAX_TABLE_ROWS = 400
            all_rows = []
            for i, e in enumerate(out["events"], 1):
                all_rows.append((
                    str(i),
                    "{:.1f}".format(e["start_time"]),
                    "{:.1f}".format(e["end_time"]),
                    str(e["duration"]),
                    "{:,}".format(e["peak"]),
                    "{:,}".format(e["total_packets"]),
                    "{:.2f}x".format(e["ratio"]),
                    e["severity"],
                    e["severity"],
                ))
            rows = all_rows[:MAX_TABLE_ROWS]

            caption = "Exported: ddos_events.csv  ·  plots/ddos.png"
            if len(out["events"]) > MAX_TABLE_ROWS:
                caption += "  ·  table shows the first {} of {:,} events".format(
                    MAX_TABLE_ROWS, len(out["events"]))

            return {
                "stats": [
                    ("Normal level", "{:.1f} pkt/s".format(out["normal"])),
                    ("Flag line",
                     "{:.1f} pkt/s".format(out["exag_level"])),
                    ("Flagged", "{0} s ({1:.2f}%)".format(
                        out["attacked_seconds"],
                        out["attacked_ratio_pct"])),
                    ("Events", str(len(out["events"]))),
                ],
                "fig": fig,
                "table": rows,
                "caption": caption,
            }

        raise ValueError("Unknown operation: " + str(op))

    # -------------------------------------------------- main-thread update

    def _finish(self, op, payload, log_text):
        if log_text.strip():
            self.log(log_text.rstrip())
        fig = payload["fig"]
        save_figure(fig, {"signal": "signal", "fourier": "fourier",
                          "filter": "filter", "conv": "convolution",
                          "system": "system", "ddos": "ddos"}[op])
        self.render_stats(payload["stats"])
        self.embed_figure(fig)
        self.plot_caption.configure(text=payload.get("caption", ""))
        if payload.get("table"):
            self.render_table(payload["table"])
        else:
            self._hide_table()
        self._set_busy(False)
        self.set_status("Done — {0}".format(OP_TITLES[op]), GREEN)
        self.log("Operation finished.", "ok")

    def _fail(self, log_text, err):
        if log_text.strip():
            self.log(log_text.rstrip())
        self.log("ERROR:\n" + err, "err")
        self._set_busy(False)
        self.set_status("Failed — check the console", RED)

    def _update_file_chip(self, st):
        name = os.path.basename(self.pcap_path or "capture.pcap")
        self.file_chip.configure(
            text="{0}  ·  {1:,} packets  ·  {2:,.0f} s".format(
                name, st["total_packets"], st["duration"]))

    # ---------------------------------------------------------- rendering

    def render_stats(self, rows):
        for child in self.stats_row.winfo_children():
            child.destroy()
        for label, value in rows:
            chip = ctk.CTkFrame(self.stats_row, fg_color=CARD,
                                corner_radius=10, border_width=1,
                                border_color=BORDER)
            chip.pack(side="left", expand=True, fill="both", padx=4, pady=2)
            ctk.CTkLabel(chip, text=label, font=FONT_TINY,
                         text_color=MUTED).pack(anchor="w", padx=12,
                                                pady=(8, 0))
            ctk.CTkLabel(chip, text=value, font=FONT_VALUE,
                         text_color=TEXT).pack(anchor="w", padx=12,
                                               pady=(0, 8))

    def embed_figure(self, fig):
        apply_dark_style()
        if self._canvas is not None:
            self._canvas.get_tk_widget().destroy()
            self._canvas = None
        if self.plot_placeholder.winfo_exists():
            self.plot_placeholder.destroy()
        canvas = FigureCanvasTkAgg(fig, master=self.plot_inner)
        canvas.draw()
        widget = canvas.get_tk_widget()
        # Never let the canvas REQUEST more space than its parcel: the small
        # configured size keeps the requested width tiny, then pack(fill)
        # stretches it to the real card area and the TkAgg <Configure> handler
        # re-renders the figure exactly at that size (no clipped titles).
        widget.configure(width=10, height=10)
        widget.pack(fill="both", expand=True)
        self._canvas = canvas
        import matplotlib.pyplot as plt
        plt.close(fig)

    def render_table(self, rows):
        if not self._table_built:
            self._build_table()
        tree = self.tree
        for item in tree.get_children():
            tree.delete(item)
        for row in rows:
            severity = row[-1]
            tree.insert("", "end", values=row[:-1], tags=(severity,))
        self.table_card.grid(row=2, column=0, sticky="ew", pady=(10, 0))

    def _build_table(self):
        self._table_built = True
        ctk.CTkLabel(self.table_card, text="DETECTED ATTACK EVENTS",
                     font=FONT_TINY, text_color=MUTED).pack(
            anchor="w", padx=16, pady=(12, 4))
        holder = ctk.CTkFrame(self.table_card, fg_color="transparent")
        holder.pack(fill="both", expand=True, padx=10, pady=(0, 12))

        self.tree = ttk.Treeview(holder, columns=TABLE_COLS, show="headings",
                                 height=6, style="DSP.Treeview")
        widths = (36, 76, 76, 56, 84, 84, 66, 96)
        for col, width in zip(TABLE_COLS, widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, anchor="center",
                             stretch=(col == "Severity"))
        for sev, color in (("CRITICAL", RED), ("HIGH", ORANGE),
                           ("MEDIUM", TEAL)):
            self.tree.tag_configure(sev, foreground=color)

        vsb = ctk.CTkScrollbar(holder, command=self.tree.yview,
                               button_color=TEAL_DIM,
                               button_hover_color=TEAL)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)

    def _hide_table(self):
        self.table_card.grid_remove()

    # ------------------------------------------------------------ helpers

    def log(self, text, tag="body"):
        self.console.insert("end", text + "\n", tag)
        try:
            self.console.see("end")
        except Exception:
            pass

    def set_status(self, text, color):
        self.status_dot.configure(text_color=color)
        self.status_label.configure(text=text)

    def _set_busy(self, busy):
        self.busy = busy
        state = "disabled" if busy else "normal"
        self.run_btn.configure(state=state)
        self.upload_btn.configure(state=state)


if __name__ == "__main__":
    app = NetworkDSPApp()
    app.mainloop()

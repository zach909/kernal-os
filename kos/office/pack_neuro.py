"""pack_neuro: Signal Lab, Neural Data Manager, and two honest "not built" entries (see docs/PACKS.md).

Signal Lab analyses a RECORDED multichannel signal that the person pastes. It does not acquire signals,
decode intent or control anything. Pure standard-library DSP with hard caps on samples, channels and filter
length. Neural Data Manager is a register of recording sessions (pseudonyms only), kept unencrypted in the
app's private vault because KOS has no encryption yet."""

from __future__ import annotations

import cmath
import math

from .packkit import app, none
from .records import Data, RecordList
from .specs import R
from .ui import Editor, Menu, Message, Prompt, Store, TextView, bar, table, today

MAX_CH, MAX_N, MAX_TAPS, MAX_EVENTS, MAX_CHARS = 8, 4096, 129, 200, 400_000
BANDS = (("delta", 0.5, 4.0), ("theta", 4.0, 8.0), ("alpha", 8.0, 13.0), ("beta", 13.0, 30.0), ("gamma", 30.0, 45.0))


# ================================================================= parsing ====
def num(s, lo=-1e9, hi=1e9):
    """Text -> finite float in [lo, hi], else None."""
    try:
        v = float(str(s).strip())
    except (TypeError, ValueError):
        return None
    return v if math.isfinite(v) and lo <= v <= hi else None


def parse_csv(text):
    """CSV, one column per channel, one row per sample -> (names, channels). Empty/nan cells are gaps (None).
    Raises ValueError for anything oversized, ragged, non-numeric or containing control characters."""
    if not isinstance(text, str) or len(text) > MAX_CHARS:
        raise ValueError("input missing or too large")
    if any(ord(c) < 32 and c not in "\n\r\t" for c in text):
        raise ValueError("control characters in input")
    rows = [[c.strip() for c in ln.replace(";", ",").split(",")] for ln in text.splitlines() if ln.strip()]
    if not rows:
        raise ValueError("no data")
    names = None
    if all(num(c) is None and c.lower() not in ("", "nan") for c in rows[0]):
        names = [c[:12] or f"ch{i + 1}" for i, c in enumerate(rows.pop(0))]
    if not rows:
        raise ValueError("no samples")
    nch = len(rows[0])
    if nch > MAX_CH:
        raise ValueError(f"at most {MAX_CH} channels")
    if len(rows) > MAX_N:
        raise ValueError(f"at most {MAX_N} samples")
    chans = [[] for _ in range(nch)]
    for i, r in enumerate(rows):
        if len(r) != nch:
            raise ValueError(f"row {i + 1} has {len(r)} columns, expected {nch}")
        for j, c in enumerate(r):
            if c == "" or c.lower() == "nan":
                chans[j].append(None)
                continue
            v = num(c)
            if v is None:
                raise ValueError(f"row {i + 1}, column {j + 1}: not a finite number")
            chans[j].append(v)
    if names is None or len(names) != nch:
        names = [f"ch{i + 1}" for i in range(nch)]
    return names, chans


def parse_events(text, n):
    """'100, 400, 700' -> sorted sample indices inside [0, n). Raises ValueError."""
    out = []
    for p in str(text).replace(";", ",").split(","):
        if p.strip():
            v = num(p, 0, n - 1)
            if v is None or v != int(v):
                raise ValueError(f"bad event index: {p.strip()[:12]!r}")
            out.append(int(v))
    if len(out) > MAX_EVENTS:
        raise ValueError(f"at most {MAX_EVENTS} events")
    return sorted(set(out))


# ====================================================================== DSP ====
def mean(x):
    return sum(x) / len(x) if x else 0.0


def remove_dc(x):
    m = mean(x)
    return [v - m for v in x]


def interpolate_gaps(x):
    """Linear interpolation over None gaps (edges take the nearest value). Returns (filled, gap_count)."""
    idx = [i for i, v in enumerate(x) if v is not None]
    if not idx:
        raise ValueError("channel has no valid samples")
    out, gaps = list(x), len(x) - len(idx)
    for i in range(len(x)):
        if x[i] is None:
            lo = max((j for j in idx if j < i), default=None)
            hi = min((j for j in idx if j > i), default=None)
            if lo is None:
                out[i] = x[hi]
            elif hi is None:
                out[i] = x[lo]
            else:
                out[i] = x[lo] + (x[hi] - x[lo]) * (i - lo) / (hi - lo)
    return out, gaps


def moving_average(x, w):
    """Centred moving average, odd window w (edges use the samples that exist)."""
    w = max(1, min(int(w), 101)) | 1
    h, n = w // 2, len(x)
    pre = [0.0]
    for v in x:
        pre.append(pre[-1] + v)
    return [(pre[min(n, i + h + 1)] - pre[max(0, i - h)]) / (min(n, i + h + 1) - max(0, i - h)) for i in range(n)]


def _lp(fc, fs, taps):
    """Hamming-windowed sinc low-pass, unit DC gain."""
    m, c = (taps - 1) / 2, 2 * fc / fs
    h = []
    for k in range(taps):
        t = k - m
        s = c if t == 0 else math.sin(math.pi * c * t) / (math.pi * t)
        h.append(s * (0.54 - 0.46 * math.cos(2 * math.pi * k / (taps - 1))))
    g = sum(h)
    return [v / g for v in h]


def fir_design(kind, fs, f1, f2=None, taps=101):
    """FIR taps. kind: lowpass | highpass | bandpass (f1..f2). Odd length, linear phase."""
    taps = max(11, min(int(taps), MAX_TAPS)) | 1
    nyq = fs / 2
    if not (0 < f1 < nyq) or (kind == "bandpass" and not (f2 and f1 < f2 < nyq)):
        raise ValueError("cut-off frequencies must satisfy 0 < f1 < f2 < fs/2")
    if kind == "lowpass":
        return _lp(f1, fs, taps)
    if kind == "highpass":
        h = [-v for v in _lp(f1, fs, taps)]
        h[taps // 2] += 1.0
        return h
    if kind == "bandpass":
        a, b = _lp(f2, fs, taps), _lp(f1, fs, taps)
        h = [p - q for p, q in zip(a, b)]
        c = sum(h[k] * math.cos(2 * math.pi * (f1 + f2) / 2 / fs * (k - taps // 2)) for k in range(taps))
        return [v / c for v in h]            # unit gain at the band centre
    raise ValueError("unknown filter kind")


def fir_apply(x, h):
    """Zero-phase convolution (centred taps; edges replicate the end samples)."""
    n, half = len(x), len(h) // 2
    pad = [x[0]] * half + list(x) + [x[-1]] * half
    return [sum(h[k] * pad[i + k] for k in range(len(h))) for i in range(n)]


def notch_apply(x, fs, f0, q=30.0):
    """RBJ biquad notch at f0 (50/60 Hz), run forward and backward so there is no phase shift."""
    if not (0 < f0 < fs / 2):
        raise ValueError("notch frequency must be between 0 and fs/2")
    w = 2 * math.pi * f0 / fs
    al, c = math.sin(w) / (2 * q), math.cos(w)
    a0 = 1 + al
    b0, b1, a1, a2 = 1 / a0, -2 * c / a0, -2 * c / a0, (1 - al) / a0

    def one(s):
        y, x1, x2, y1, y2 = [], s[0], s[0], s[0], s[0]
        for v in s:
            o = b0 * v + b1 * x1 + b0 * x2 - a1 * y1 - a2 * y2
            x2, x1, y2, y1 = x1, v, y1, o
            y.append(o)
        return y
    return one(one(x)[::-1])[::-1]


def fft(x):
    """Radix-2 FFT of a list whose length is a power of two (our own, iterative)."""
    n = len(x)
    if n < 1 or n & (n - 1) or n > 2 * MAX_N:
        raise ValueError("length must be a power of two, at most %d" % (2 * MAX_N))
    a = [complex(v) for v in x]
    j = 0
    for i in range(1, n):
        bit = n >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j |= bit
        if i < j:
            a[i], a[j] = a[j], a[i]
    size = 2
    while size <= n:
        wl = cmath.exp(-2j * math.pi / size)
        for s in range(0, n, size):
            w = 1 + 0j
            for k in range(size // 2):
                u, v = a[s + k], a[s + k + size // 2] * w
                a[s + k], a[s + k + size // 2] = u + v, u - v
                w *= wl
        size <<= 1
    return a


def psd(x, fs):
    """One-sided Hann-windowed power spectrum of a DC-removed signal -> (freqs, powers), bin spacing fs/N."""
    n = 1
    while n < len(x):
        n <<= 1
    x = remove_dc(x)
    m = len(x)
    w = [0.5 - 0.5 * math.cos(2 * math.pi * i / max(1, m - 1)) for i in range(m)]
    xs = [x[i] * w[i] for i in range(m)] + [0.0] * (n - m)
    spec = fft(xs)
    return [k * fs / n for k in range(n // 2 + 1)], [abs(spec[k]) ** 2 for k in range(n // 2 + 1)]


def band_powers(x, fs):
    """{band: relative power} over the bands that fit below Nyquist (sum of band powers = 1)."""
    f, p = psd(x, fs)
    tot, out = {}, {}
    for name, lo, hi in BANDS:
        if lo < fs / 2:
            tot[name] = sum(pv for fv, pv in zip(f, p) if lo <= fv < hi)
    s = sum(tot.values())
    for k, v in tot.items():
        out[k] = v / s if s > 0 else 0.0
    return out


def dominant_freq(x, fs, fmin=0.5):
    f, p = psd(x, fs)
    best = max((i for i in range(len(f)) if f[i] >= fmin), key=lambda i: p[i], default=None)
    return f[best] if best is not None and p[best] > 0 else 0.0


def epochs_average(x, events, pre, post):
    """Average of x[e-pre : e+post] around each event, baseline (mean of the pre part) removed.
    Returns (average, used, skipped). Events too near the ends are skipped."""
    if pre < 0 or post < 1 or pre + post > MAX_N:
        raise ValueError("bad epoch window")
    acc, used = [0.0] * (pre + post), 0
    for e in events[:MAX_EVENTS]:
        if e - pre < 0 or e + post > len(x):
            continue
        seg = x[e - pre:e + post]
        base = mean(seg[:pre]) if pre else 0.0
        for i, v in enumerate(seg):
            acc[i] += v - base
        used += 1
    if not used:
        raise ValueError("no event has a full window inside the recording")
    return [v / used for v in acc], used, min(len(events), MAX_EVENTS) - used


def artifacts(x, fs, thr=None):
    """Per-channel quality flags for a gap-free list. thr: optional |x - mean| amplitude limit."""
    n, flags = len(x), {}
    run = best = 1
    for i in range(1, n):
        run = run + 1 if abs(x[i] - x[i - 1]) < 1e-12 else 1
        best = max(best, run)
    flags["flat_run"] = best
    flags["flatline"] = best >= max(10, int(0.25 * fs))
    hi, lo = max(x), min(x)
    ch, cl = sum(1 for v in x if v == hi), sum(1 for v in x if v == lo)
    flags["clipped"] = hi != lo and (ch >= max(3, n // 100) or cl >= max(3, n // 100))
    m = mean(x)
    flags["over_thr"] = sum(1 for v in x if thr is not None and abs(v - m) > thr)
    if fs > 100 and n >= 16:
        f, p = psd(x, fs)
        tot = sum(p[1:]) or 1.0
        flags["hf_ratio"] = sum(pv for fv, pv in zip(f, p) if fv >= 40) / tot
    else:
        flags["hf_ratio"] = None
    flags["noisy"] = flags["hf_ratio"] is not None and flags["hf_ratio"] > 0.5
    return flags


def quality_lines(names, chans, fs, thr=None):
    """Plain per-channel report. Channels may contain None gaps; they are interpolated for the checks."""
    rows = []
    for nm, ch in zip(names, chans):
        try:
            x, gaps = interpolate_gaps(ch)
        except ValueError:
            rows.append([nm, "no data", "", "", "", ""]); continue
        a = artifacts(x, fs, thr)
        bad = [t for t, on in (("flat", a["flatline"]), ("clip", a["clipped"]), ("noisy", a["noisy"]),
                               ("over-thr", a["over_thr"] > 0), ("gaps", gaps > 0)) if on]
        rows.append([nm, "BAD" if any(t in bad for t in ("flat", "clip", "noisy")) else ("CHECK" if bad else "ok"),
                     gaps, a["flat_run"], "n/a" if a["hf_ratio"] is None else f"{a['hf_ratio']:.2f}", ",".join(bad) or "-"])
    return table(rows, ["channel", "status", "gaps", "flat run", "HF ratio", "flags"])


# ==================================================================== ASCII ====
def plot(x, width=64, height=12):
    """Min/max-per-column ASCII trace of x."""
    width, height = max(8, min(width, 100)), max(4, min(height, 30))
    lo, hi = min(x), max(x)
    span = (hi - lo) or 1.0
    grid = [[" "] * width for _ in range(height)]
    for c in range(width):
        seg = x[c * len(x) // width:max(c * len(x) // width + 1, (c + 1) * len(x) // width)]
        a = int((min(seg) - lo) / span * (height - 1))
        b = int((max(seg) - lo) / span * (height - 1))
        for r in range(a, b + 1):
            grid[height - 1 - r][c] = "*"
    return [f"{hi:>10.4g} |" + "".join(grid[0])] + ["           |" + "".join(r) for r in grid[1:-1]] + \
           [f"{lo:>10.4g} |" + "".join(grid[-1]), "           +" + "-" * width]


def spectrum_lines(x, fs, fmax=60.0, rows=24):
    f, p = psd(x, fs)
    fmax = min(fmax, fs / 2)
    step = fmax / rows
    cells = [max([pv for fv, pv in zip(f, p) if i * step <= fv < (i + 1) * step] or [0.0]) for i in range(rows)]
    top = max(cells) or 1.0
    return [f"{i * step:6.1f} Hz {bar(c, top, 40)}" for i, c in enumerate(cells)]


# ================================================================ Signal Lab ====
NOTE_LAB = ("Offline analysis of a RECORDED signal you paste (CSV, one column per channel; empty or nan cells are dropped samples). "
            "It does not acquire signals, decode intent or control anything. Limits: 8 channels, 4096 samples.")


def demo_csv(fs=250):
    """A small synthetic 2-channel recording: 10 Hz alpha + 50 Hz mains, and 20 Hz with a dropped stretch."""
    rows = ["alpha10,beta20"]
    for i in range(1000):
        t = i / fs
        a = 20 * math.sin(2 * math.pi * 10 * t) + 8 * math.sin(2 * math.pi * 50 * t)
        b = "" if 400 <= i < 404 else f"{10 * math.sin(2 * math.pi * 20 * t):.3f}"
        rows.append(f"{a:.3f},{b}")
    return "\n".join(rows)


class Lab:
    """The working state: original and working channels, sample rate, events."""

    def __init__(self, host):
        self.store = Store(host)
        d = self.store.load("lab") or {}
        self.fs, self.events, self.thr = d.get("fs", 250.0), d.get("events", []), d.get("thr")
        self.csv, self.names, self.orig = d.get("csv", ""), [], []
        if self.csv:
            try:
                self.names, self.orig = parse_csv(self.csv)
            except ValueError:
                self.csv = ""
        self.work = [list(c) for c in self.orig]
        self.log = []

    def save(self):
        self.store.save("lab", {"csv": self.csv, "fs": self.fs, "events": self.events, "thr": self.thr})

    def load(self, text):
        self.names, self.orig = parse_csv(text)
        self.csv, self.work, self.log = text, [list(c) for c in self.orig], []
        self.events = [e for e in self.events if e < len(self.orig[0])]
        self.save()

    def ready(self):
        return bool(self.orig)

    def clean(self, i):
        """Channel i with gaps interpolated (not stored)."""
        return interpolate_gaps(self.work[i])[0]

    def apply(self, fn):
        """Run fn(channel)->channel on every channel (gaps are interpolated first)."""
        self.work = [fn(self.clean(i)) for i in range(len(self.work))]


class PasteEditor(Editor):
    """Editor whose Ctrl-S loads the text and shows the reason if it is refused."""

    def save(self):
        try:
            self.on_save(self.area.text)
        except ValueError as e:
            self.flash = ("not loaded: " + str(e))[:70]
            return
        self.area.dirty = False
        self.flash = "loaded"


def make_lab(host, entry):
    lab = Lab(host)

    def need():
        return None if lab.ready() else ("push", Message("Signal Lab", ["Load a recording first."]))

    def view(title, lines):
        return ("push", TextView(title, lines))

    def err(e):
        return ("push", Message("Not done", [str(e)[:200]]))

    def do_load(text):
        try:
            lab.load(text)
        except ValueError as e:
            return err(e)
        return view("Loaded", [f"{len(lab.orig)} channel(s): {', '.join(lab.names)}", f"{len(lab.orig[0])} samples",
                               f"sample rate {lab.fs:g} Hz (set it with 'Sample rate')", "Stored unencrypted in this app's vault."])

    def paste():
        return ("push", PasteEditor("Paste CSV", lab.csv, lab.load, hint="Ctrl-S loads"))

    def demo():
        lab.fs = 250.0
        return do_load(demo_csv())

    def set_fs(v):
        n = num(v, 1, 100000)
        if n is None:
            return err("sample rate must be 1 to 100000 Hz")
        lab.fs = n
        lab.save()

    def set_events(v):
        try:
            lab.events = parse_events(v, len(lab.orig[0]))
        except ValueError as e:
            return err(e)
        lab.save()

    def set_thr(v):
        lab.thr = num(v, 0, 1e9) if v.strip() else None
        lab.save()

    def quality():
        r = need()
        if r:
            return r
        return view("Quality", quality_lines(lab.names, lab.work, lab.fs, lab.thr) +
                    ["", "BAD = flat-line, clipping or high-frequency noise (>50% of power above 40 Hz).",
                     f"Amplitude threshold: {lab.thr if lab.thr is not None else 'not set'}"])

    def spectra():
        r = need()
        if r:
            return r
        out = []
        for i, nm in enumerate(lab.names):
            x = lab.clean(i)
            bp = band_powers(x, lab.fs)
            out += [f"{nm}: dominant {dominant_freq(x, lab.fs):.2f} Hz"] + \
                   [f"  {k:<6}{v * 100:5.1f}% {bar(v, 1.0, 30)}" for k, v in bp.items()] + [""]
        return view("Band powers", out)

    def spec_plot(i):
        return lambda: view("Spectrum " + lab.names[i], spectrum_lines(lab.clean(i), lab.fs))

    def trace(i):
        return lambda: view("Trace " + lab.names[i], plot(lab.clean(i)) + [f"{len(lab.work[i])} samples at {lab.fs:g} Hz"])

    def pick(title, fn):
        r = need()
        if r:
            return r
        return ("push", Menu(title, [(n, fn(i)) for i, n in enumerate(lab.names)]))

    def run_filter(kind):
        def go(v):
            p = [num(s, 0, 1e6) for s in v.replace(" ", "").split(",") if s]
            try:
                if kind == "ma":
                    lab.apply(lambda x: moving_average(x, int(p[0])))
                elif kind == "dc":
                    lab.apply(remove_dc)
                elif kind == "notch":
                    lab.apply(lambda x: notch_apply(x, lab.fs, p[0]))
                else:
                    h = fir_design(kind, lab.fs, p[0], p[1] if len(p) > 1 else None)
                    lab.apply(lambda x: fir_apply(x, h))
            except (ValueError, IndexError, TypeError) as e:
                return err(e if str(e) else "check the parameters")
            lab.log.append(f"{kind} {v}".strip())
            return view("Applied", ["Working copy: " + ", ".join(lab.log), "(Reset restores the original.)"])
        return go

    def ask_filter(kind, label):
        def go():
            r = need()
            return r or ("push", Prompt(label, label, "", run_filter(kind)))
        return go

    def reset():
        lab.work, lab.log = [list(c) for c in lab.orig], []
        return view("Reset", ["Working copy restored from the recording."])

    def fill():
        r = need()
        if r:
            return r
        out = []
        for i, nm in enumerate(lab.names):
            try:
                lab.work[i], g = interpolate_gaps(lab.work[i])
            except ValueError:
                g = 0
            out.append(f"{nm}: {g} gap sample(s) interpolated")
        return view("Gaps", out)

    def epoch_run(v):
        p = [num(s, 0, 1e5) for s in v.replace(" ", "").split(",")]
        if len(p) != 2 or None in p:
            return err("enter 'before,after' in seconds, e.g. 0.2,0.8")
        pre, post = int(p[0] * lab.fs), int(p[1] * lab.fs)
        out = []
        for i, nm in enumerate(lab.names):
            try:
                avg, used, skipped = epochs_average(lab.clean(i), lab.events, pre, post)
            except ValueError as e:
                return err(e)
            out += [f"{nm}: {used} epoch(s) averaged, {skipped} skipped", *plot(avg, 60, 8), ""]
        return view("Epoch average", out)

    def epochs():
        r = need()
        if r:
            return r
        if not lab.events:
            return err("set event markers first")
        return ("push", Prompt("Epochs", "Seconds before,after the event:", "0.2,0.8", epoch_run))

    ents = [("Paste a recording (CSV)", paste), ("Load a synthetic demo", demo),
            ("Sample rate (Hz)", lambda: ("push", Prompt("Rate", "Sample rate in Hz:", f"{lab.fs:g}", set_fs))),
            ("Event markers (sample numbers)", lambda: need() or ("push", Prompt("Events", "Sample indices, comma separated:", ",".join(map(str, lab.events)), set_events))),
            ("Artifact amplitude threshold", lambda: ("push", Prompt("Threshold", "Max |value - mean| (blank = off):", "" if lab.thr is None else f"{lab.thr:g}", set_thr))),
            ("Quality report", quality), ("Band powers and dominant frequency", spectra),
            ("Spectrum plot", lambda: pick("Spectrum", spec_plot)), ("Trace plot", lambda: pick("Trace", trace)),
            ("Fill dropped samples", fill), ("Remove DC offset", lambda: need() or (lab.apply(remove_dc), view("DC", ["Mean removed."]))[1]),
            ("Moving average", ask_filter("ma", "Window (samples, odd)")),
            ("Low-pass FIR", ask_filter("lowpass", "Cut-off Hz")), ("High-pass FIR", ask_filter("highpass", "Cut-off Hz")),
            ("Band-pass FIR", ask_filter("bandpass", "Low,high Hz")), ("Notch 50/60 Hz", ask_filter("notch", "Mains Hz")),
            ("Epoch average around events", epochs), ("Reset working copy", reset)]
    return Menu("Signal Lab", ents, ["  Analyses a recording. It does not acquire signals or decode anything.", ""])


# ===================================================== Neural Data Manager ====
NOTE_NDM = ("Register of recording sessions: subject pseudonym only (never real names), consent yes/no/date, device, rate, channels, "
            "duration, tags, storage location, retention expiry, notes; reports on expired retention, missing consent and totals. "
            "It lists recordings, it does not hold or read them. Neural recordings are sensitive personal data: the register is stored "
            "UNENCRYPTED in this app's private vault because KOS has no encryption yet.")


def ndm_report(items):
    """Expired retention, missing consent and totals. Tolerates missing or odd fields."""
    now = today()
    exp = [r for r in items if str(r.get("retention_until") or "") and str(r["retention_until"]) < now]
    nocon = [r for r in items if r.get("consent") != "yes"]

    def n(r, k):
        v = num(r.get(k), 0, 1e9)
        return v or 0.0
    hrs = sum(n(r, "duration_min") for r in items) / 60
    return (["EXPIRED RETENTION (delete or review):"] + [f"  {r.get('session', '?')}  {r.get('subject', '?')}  until {r['retention_until']}  at {r.get('location') or '?'}" for r in exp[:200]]
            + (["  none"] if not exp else []) + ["", "CONSENT NOT RECORDED AS YES:"]
            + [f"  {r.get('session', '?')}  {r.get('subject', '?')}  consent={r.get('consent') or 'unset'}" for r in nocon[:200]]
            + (["  none"] if not nocon else [])
            + ["", f"Totals: {len(items)} session(s), {hrs:.1f} h, {len({r.get('subject') for r in items})} subject(s)",
               "Pseudonyms only. Stored unencrypted: KOS has no encryption yet."])


SPEC_NDM = R("neural", "Neural Data Manager", "session",
             "session*; subject*; consent: choice(yes|no|unknown)=unknown; consent_date: date; device; sample_rate_hz: number; channels: number; "
             "duration_min: number; tags: tags; location; retention_until: date; notes: long",
             list_cols=("session", "subject", "consent", "retention_until"), due="retention_until",
             blurb="Pseudonym only, never a real name. Stored unencrypted in this app's vault.",
             report=ndm_report, report_label="Retention, consent, totals")


def make_ndm(host, entry):
    return RecordList(Data(host, SPEC_NDM))


# ===================================================================== ENTRIES ====
ENTRIES: list = [
    app("Signal Lab", make_lab, "partial", NOTE_LAB),
    app("Neural Data Manager", make_ndm, "partial", NOTE_NDM),
    none("Neural Interface Devices",
         "Brain-computer interfaces, signal acquisition, thought-to-text, neural keyboard/mouse, intent recognition and device monitoring need sensors, "
         "real-time processing and device access apps never get. Signal Lab covers recorded data only; `kos usb` and `kos firmware` are not neural links."),
    none("Assistive and Clinical Control",
         "Prosthetic and mobility control, sensory/haptic feedback, neurofeedback, rehabilitation and memory aids are safety-critical medical "
         "functions. KOS will not simulate them or imply they work, and a sandboxed app has no device path to them."),
]

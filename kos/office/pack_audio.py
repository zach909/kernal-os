"""pack_audio: Music Studio, Sound Synthesizer, Audio Editor, Music Library, Podcast Manager, News Reader.

KOS has no audio device and no network: these apps CREATE and EDIT audio files and feed text in the vault. Nothing
plays sound, nothing fetches a feed. Audio files live in the text vault as base64 (`name.wav.b64`, like the images in
pixels.py); a vault value is at most 400,000 characters, so a WAV is capped at MAXWAV bytes (about 18 s at 8 kHz).
Feeds are parsed with xml.etree after refusing any DOCTYPE/ENTITY (entity-expansion bombs) and capping the size."""

from __future__ import annotations

import base64
import binascii
import io
import math
import random
import re
import struct
import time
import wave
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from html import unescape
from xml.sax.saxutils import escape, quoteattr

from .packkit import app, shared_add
from .records import Data, RecordList
from .specs import R
from .ui import SpaceHost, Confirm, Editor, ListNav, Menu, Message, Prompt, Screen, Store, TextView, slug, table, wrap

MAXWAV = 290_000                      # bytes; base64 of this is < the 400,000-character vault limit
MAXFRAMES = (MAXWAV - 44) // 2        # 16-bit samples that fit
MAXTEXT = 20_000                      # a score or patch
MAXFEED = 200_000                     # a pasted feed


# ================================================================ WAV I/O ====
@dataclass
class Wav:
    rate: int
    ch: int
    data: list                        # interleaved signed 16-bit ints

    @property
    def frames(self): return len(self.data) // self.ch


def clip(v) -> int:
    return -32768 if v < -32768 else 32767 if v > 32767 else int(v)


def wav_bytes(w: Wav) -> bytes:
    if len(w.data) * 2 + 44 > MAXWAV:
        raise ValueError(f"too long: a WAV here holds at most {MAXFRAMES // w.ch} frames at {w.ch} channel(s)")
    buf = io.BytesIO()
    with wave.open(buf, "wb") as f:
        f.setnchannels(w.ch); f.setsampwidth(2); f.setframerate(w.rate)
        f.writeframes(struct.pack(f"<{len(w.data)}h", *w.data))
    return buf.getvalue()


def read_wav(b: bytes) -> Wav:
    """16-bit PCM mono/stereo only; anything else (or anything huge) is refused."""
    if len(b) > MAXWAV:
        raise ValueError("file too large for this app")
    if b[:4] != b"RIFF" or b[8:12] != b"WAVE":
        raise ValueError("not a WAV file")
    try:
        with wave.open(io.BytesIO(b)) as f:
            ch, sw, rate = f.getnchannels(), f.getsampwidth(), f.getframerate()
            if sw != 2 or ch not in (1, 2) or not 1000 <= rate <= 96000:
                raise ValueError("only 16-bit PCM mono or stereo WAV (1-96 kHz) is supported")
            raw = f.readframes(min(f.getnframes(), MAXFRAMES))
    except (wave.Error, EOFError, struct.error) as e:
        raise ValueError(f"not a valid WAV file: {e}")
    n = len(raw) // (2 * ch) * ch
    if not n:
        raise ValueError("WAV has no audio")
    return Wav(rate, ch, list(struct.unpack(f"<{n}h", raw[:n * 2])))


def load_b64(host, key: str) -> bytes:
    v = host.get(key)
    if v is None:
        raise ValueError(f"no vault key '{key}'")
    try:
        return base64.b64decode(v, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError(f"'{key}' is not base64 data")


def save_b64(host, key: str, data: bytes) -> None:
    if not host.put(key, base64.b64encode(data).decode()):
        raise ValueError(getattr(host, "error", "") or f"could not save '{key}'")


def num(tok, lo, hi, what):
    try:
        v = float(tok)
    except (TypeError, ValueError):
        raise ValueError(f"{what}: '{tok}' is not a number")
    if not math.isfinite(v) or not lo <= v <= hi:
        raise ValueError(f"{what}: must be {lo:g} to {hi:g}")
    return v


# ============================================================ Music Studio ====
TPQ = 480                                              # MIDI ticks per quarter note
DURS = {"w": 4 * TPQ, "h": 2 * TPQ, "q": TPQ, "e": TPQ // 2, "s": TPQ // 4, "t": TPQ // 8}
SEMI = {"C": 0, "D": 2, "E": 4, "F": 5, "G": 7, "A": 9, "B": 11}
_NOTE = re.compile(r"^([A-Ga-g])([#b]?)(-?\d)$")
SCORE_RATE = 8000
SCORE_HELP = """tempo 120            beats (quarter notes) per minute, 20-300
track Lead           start a new track (up to 8); lines before it are track 1
program 24           MIDI instrument 0-127 for this track (MIDI file only)
C4 q E4 q G4 h       note then length, in pairs: w whole h half q quarter e eighth
                     s sixteenth t thirty-second; add . to dot it (q.)
Bb3 e  F#5 s         flat b, sharp #, octave -1..9 (C4 = middle C, MIDI 60)
R q                  a rest
; comment

Each track plays one note at a time; tracks play together. The WAV is a plain sine
mix at 8 kHz; the MIDI file is type 1 (one tempo track + one track per part).
Nothing can be played here: export, then use a player on another machine."""
SCORE_EXAMPLE = "tempo 120\ntrack Melody\nC4 q E4 q G4 q C5 h\ntrack Bass\nC3 h G2 h\n"


@dataclass
class Score:
    tempo: int
    tracks: list                      # [{"name", "program", "ev": [(start_tick, dur_tick, midi|None)]}]

    @property
    def ticks(self):
        return max([e[0] + e[1] for t in self.tracks for e in t["ev"]] or [0])


def parse_score(text: str) -> Score:
    if len(text) > MAXTEXT:
        raise ValueError("score too long")
    tempo, tracks, cur, count = 120, [], None, 0

    def new(name):
        if len(tracks) >= 8:
            raise ValueError("at most 8 tracks")
        t = {"name": name[:40] or f"Track {len(tracks) + 1}", "program": None, "ev": [], "at": 0}
        tracks.append(t); return t

    for n, line in enumerate(text.split("\n"), 1):
        line = "".join(c for c in line.split(";")[0] if c.isprintable()).strip()
        if not line:
            continue
        p = line.split()
        try:
            if p[0].lower() == "tempo" and len(p) == 2:
                tempo = int(num(p[1], 20, 300, "tempo"))
            elif p[0].lower() == "track":
                cur = new(" ".join(p[1:]))
            elif p[0].lower() == "program" and len(p) == 2:
                cur = cur or new("")
                cur["program"] = int(num(p[1], 0, 127, "program"))
            else:
                if len(p) % 2:
                    raise ValueError("notes come in pairs: NOTE LENGTH")
                cur = cur or new("")
                for a, b in zip(p[::2], p[1::2]):
                    d = DURS.get(b[:1].lower())
                    if d is None or b[1:] not in ("", "."):
                        raise ValueError(f"bad length '{b}'")
                    if b.endswith("."):
                        d = d * 3 // 2
                    if a.lower() == "r":
                        pitch = None
                    else:
                        m = _NOTE.match(a)
                        if not m:
                            raise ValueError(f"bad note '{a}'")
                        pitch = 12 * (int(m[3]) + 1) + SEMI[m[1].upper()] + {"#": 1, "b": -1, "": 0}[m[2]]
                        if not 0 <= pitch <= 127:
                            raise ValueError(f"note '{a}' out of range")
                    count += 1
                    if count > 2000:
                        raise ValueError("at most 2000 notes")
                    cur["ev"].append((cur["at"], d, pitch)); cur["at"] += d
        except ValueError as e:
            raise ValueError(f"line {n}: {e}")
    if not any(e[2] is not None for t in tracks for e in t["ev"]):
        raise ValueError("the score has no notes")
    return Score(tempo, tracks)


def vlq(n: int) -> bytes:
    out = [n & 0x7F]
    n >>= 7
    while n:
        out.append((n & 0x7F) | 0x80); n >>= 7
    return bytes(reversed(out))


def midi_bytes(sc: Score) -> bytes:
    def chunk(tag, body): return tag + struct.pack(">I", len(body)) + body
    tempo = chunk(b"MTrk", vlq(0) + b"\xff\x51\x03" + (60_000_000 // sc.tempo).to_bytes(3, "big")
                  + vlq(0) + b"\xff\x58\x04\x04\x02\x18\x08" + vlq(0) + b"\xff\x2f\x00")
    parts = [tempo]
    chans = [c for c in range(16) if c != 9]               # channel 10 is percussion
    for i, t in enumerate(sc.tracks):
        ch, name = chans[i % 15], t["name"].encode("utf-8")[:60]
        evs = [(0, 0, b"\xff\x03" + vlq(len(name)) + name)]
        if t["program"] is not None:
            evs.append((0, 1, bytes([0xC0 | ch, t["program"]])))
        for s, d, p in t["ev"]:
            if p is not None:
                evs.append((s, 3, bytes([0x90 | ch, p, 80])))
                evs.append((s + d, 2, bytes([0x80 | ch, p, 0])))       # an off sorts before the next on
        evs.sort(key=lambda e: (e[0], e[1]))
        body, last = b"", 0
        for tick, _o, data in evs:
            body += vlq(tick - last) + data; last = tick
        parts.append(chunk(b"MTrk", body + vlq(0) + b"\xff\x2f\x00"))
    return chunk(b"MThd", struct.pack(">HHH", 1, len(parts), TPQ)) + b"".join(parts)


def render_score(sc: Score, rate: int = SCORE_RATE) -> Wav:
    def frame(tick): return round(tick * 60 / sc.tempo / TPQ * rate)
    n = frame(sc.ticks)
    if n > MAXFRAMES:
        raise ValueError(f"too long for a WAV here: {n / rate:.1f} s, the limit is {MAXFRAMES / rate:.1f} s")
    mix, amp = [0.0] * n, 0.9 / len(sc.tracks)
    for t in sc.tracks:
        for s, d, p in t["ev"]:
            if p is None:
                continue
            a, b = frame(s), frame(s + d)
            w, edge = 2 * math.pi * 440 * 2 ** ((p - 69) / 12) / rate, max(1, min(40, (b - a) // 4))
            for i in range(b - a):
                mix[a + i] += amp * min(1.0, i / edge, (b - a - i) / edge) * math.sin(w * i)
    return Wav(rate, 1, [clip(round(v * 32767)) for v in mix])


def build_score(text: str):
    sc = parse_score(text)
    w = render_score(sc)
    return ({"song.wav.b64": wav_bytes(w), "song.mid.b64": midi_bytes(sc)},
            [f"{len(sc.tracks)} track(s), tempo {sc.tempo}, {w.frames / w.rate:.2f} s.",
             "song.wav (8 kHz mono sine mix) and song.mid (type 1)"])


# ========================================================= Sound Synthesizer ==
WAVES = ("sine", "square", "saw", "triangle")
SYNTH_EXAMPLE = "osc saw 220 0.6\nosc square 110 0.3\nnoise 0.05\nadsr 0.05 0.2 0.6 0.3\nlfo 5 0.3\ndur 1.5\nrate 8000\n"
SYNTH_HELP = """osc sine|square|saw|triangle HZ [LEVEL]   an oscillator (up to 8; level 0-1, default 1)
noise LEVEL                               white noise (fixed seed, so repeatable)
adsr A D S R                              attack s, decay s, sustain level 0-1, release s
lfo RATE DEPTH                            tremolo: RATE Hz (0.1-50), DEPTH 0-1
dur SECONDS                               0.05 to 10 (also limited by the file size cap)
rate HZ                                   4000 to 22050 (default 8000); keep tones below half of it
; comment

The mix is scaled so it never clips. Output: synth.wav in the vault. It cannot be played here."""


def parse_patch(text: str) -> dict:
    if len(text) > MAXTEXT:
        raise ValueError("patch too long")
    P = {"osc": [], "noise": 0.0, "adsr": (0.01, 0.1, 0.8, 0.1), "lfo": None, "dur": 1.0, "rate": 8000}
    for n, line in enumerate(text.split("\n"), 1):
        line = "".join(c for c in line.split(";")[0] if c.isprintable()).strip()
        if not line:
            continue
        p = line.lower().split()
        try:
            if p[0] == "osc" and len(p) in (3, 4):
                if p[1] not in WAVES or len(P["osc"]) >= 8:
                    raise ValueError("osc " + "|".join(WAVES) + " HZ [LEVEL], at most 8")
                P["osc"].append((p[1], num(p[2], 1, 22050, "hz"), num(p[3], 0, 1, "level") if len(p) == 4 else 1.0))
            elif p[0] == "noise" and len(p) == 2:
                P["noise"] = num(p[1], 0, 1, "noise level")
            elif p[0] == "adsr" and len(p) == 5:
                P["adsr"] = (num(p[1], 0, 10, "attack"), num(p[2], 0, 10, "decay"), num(p[3], 0, 1, "sustain"), num(p[4], 0, 10, "release"))
            elif p[0] == "lfo" and len(p) == 3:
                P["lfo"] = (num(p[1], 0.1, 50, "lfo rate"), num(p[2], 0, 1, "lfo depth"))
            elif p[0] == "dur" and len(p) == 2:
                P["dur"] = num(p[1], 0.05, 10, "dur")
            elif p[0] == "rate" and len(p) == 2:
                P["rate"] = int(num(p[1], 4000, 22050, "rate"))
            else:
                raise ValueError(f"unknown or incomplete '{p[0]}'")
        except ValueError as e:
            raise ValueError(f"line {n}: {e}")
    if not P["osc"] and not P["noise"]:
        raise ValueError("add at least one osc or noise line")
    if any(f > P["rate"] / 2 for _w, f, _l in P["osc"]):
        raise ValueError("an oscillator is above half the sample rate")
    if round(P["dur"] * P["rate"]) > MAXFRAMES:
        raise ValueError(f"too long for the file cap: at most {MAXFRAMES / P['rate']:.1f} s at {P['rate']} Hz")
    return P


def _osc(kind: str, p: float) -> float:
    if kind == "sine": return math.sin(2 * math.pi * p)
    if kind == "square": return 1.0 if p < 0.5 else -1.0
    if kind == "saw": return 2 * p - 1
    return 4 * abs(((p - 0.25) % 1) - 0.5) - 1


def envelope(t: float, D: float, a: float, d: float, s: float, r: float) -> float:
    def gate(x):
        if a and x < a: return x / a
        if d and x < a + d: return 1 - (1 - s) * (x - a) / d
        return s if (a or d) or x >= 0 else 1.0
    hold = D - r
    if t < hold or not r:
        return gate(t)
    return gate(hold) * max(0.0, (D - t) / r)


def synth(P: dict) -> Wav:
    rate, D = P["rate"], P["dur"]
    n, rng = round(D * rate), random.Random(1)
    a, d, s, r = P["adsr"]
    norm = max(1.0, sum(l for _w, _f, l in P["osc"]) + P["noise"])
    out = []
    for i in range(n):
        t = i / rate
        v = sum(l * _osc(k, (f * t) % 1.0) for k, f, l in P["osc"]) + P["noise"] * rng.uniform(-1, 1)
        g = envelope(t, D, a, d, s, r)
        if P["lfo"]:
            f, depth = P["lfo"]
            g *= 1 - depth * (0.5 - 0.5 * math.cos(2 * math.pi * f * t))        # starts at full level
        out.append(clip(round(0.9 * 32767 * g * v / norm)))
    return Wav(rate, 1, out)


def build_patch(text: str):
    w = synth(parse_patch(text))
    return {"synth.wav.b64": wav_bytes(w)}, [f"{w.frames / w.rate:.2f} s at {w.rate} Hz, 16-bit mono.", "synth.wav in the vault"]


def workshop(host, title: str, key: str, example: str, help_text: str, build, ext: str, register=None) -> Screen:
    """Edit a text document, then turn it into audio files in the vault."""
    def text(): return host.get(key) or example

    def edit():
        return ("push", Editor(title + " - " + key, text(), on_save=lambda t: host.put(key, t), hint="(Ctrl-S saves)"))

    def export():
        try:
            files, info = build(text())
            for name, data in files.items():
                save_b64(host, name, data)
        except ValueError as e:
            return ("push", Message("Cannot export", [str(e)]))
        if register:
            info = info + [register(files)]
        return ("push", Message("Exported", info + ["Stored as base64 text in the vault (" + ext + ").",
                                                    "This device cannot play sound; copy the files to a player."]))

    return Menu(title, [(f"Edit the {key}", edit), ("Export to the vault", export),
                        ("Syntax help", lambda: ("push", TextView("Help", help_text.split("\n"))))],
                intro=["  Compose or design as text, export real audio files. No playback here."])


def register_song(host):
    """Add the exported composition to the Music Library's shared 'music' folder (needs a write grant)."""
    def reg(files):
        w = read_wav(files["song.wav.b64"])
        ok = shared_add(host, "music", {"title": "Studio song " + time.strftime("%Y-%m-%d %H:%M"), "artist": "Music Studio",
                                         "album": "", "seconds": str(round(w.frames / w.rate)), "file": "song.wav.b64"})
        return "Registered in the Music Library." if ok else "Not registered in the Music Library: no write access to the shared 'music' folder (grant it with kos grant)."
    return reg


# ================================================================ Audio Editor ==
def apply_cmd(w: Wav, line: str, load) -> Wav:
    p = line.lower().split()
    if not p:
        raise ValueError("type a command, ? for the list")
    op, a = p[0], p[1:]
    ch, rate, N = w.ch, w.rate, w.frames
    if op == "trim" and len(a) in (1, 2):
        s = round(num(a[0], 0, 1e6, "start") * rate)
        e = round(num(a[1], 0, 1e6, "end") * rate) if len(a) == 2 else N
        if not 0 <= s < e <= N:
            raise ValueError(f"trim range must be inside 0 - {N / rate:.3f} s")
        return Wav(rate, ch, w.data[s * ch:e * ch])
    if op == "gain" and len(a) == 1:
        k = 10 ** (num(a[0], -60, 60, "dB") / 20)
        return Wav(rate, ch, [clip(round(v * k)) for v in w.data])
    if op in ("fadein", "fadeout") and len(a) == 1:
        n = min(N, round(num(a[0], 0, 1e6, "seconds") * rate))
        d = list(w.data)
        for f in range(n):
            fr, k = (f, f / n) if op == "fadein" else (N - n + f, (n - 1 - f) / n)
            for c in range(ch):
                d[fr * ch + c] = clip(round(d[fr * ch + c] * k))
        return Wav(rate, ch, d)
    if op == "normalize" and not a:
        peak = max(abs(v) for v in w.data)
        return w if not peak else Wav(rate, ch, [clip(round(v * 32767 / peak)) for v in w.data])
    if op == "reverse" and not a:
        fr = [w.data[i * ch:(i + 1) * ch] for i in range(N)]
        return Wav(rate, ch, [v for f in reversed(fr) for v in f])
    if op == "mono" and not a:
        if ch == 1:
            raise ValueError("already mono")
        return Wav(rate, 1, [(w.data[i] + w.data[i + 1]) // 2 for i in range(0, len(w.data), 2)])
    if op == "concat" and len(a) == 1:
        o = load(line.split(None, 1)[1].strip())
        if (o.rate, o.ch) != (rate, ch):
            raise ValueError(f"format differs: need {rate} Hz / {ch} ch, got {o.rate} Hz / {o.ch} ch")
        if len(w.data) + len(o.data) > MAXFRAMES:
            raise ValueError("result would be too large")
        return Wav(rate, ch, w.data + o.data)
    raise ValueError("commands: trim S [E] | gain DB | fadein S | fadeout S | normalize | reverse | mono | concat KEY")


class AudioEditor(Screen):
    title = "Audio Editor"

    def __init__(self, host):
        self.host, self.w, self.name, self.prev, self.msg = host, None, "", [], ""
        self.nav = ListNav(0)
        self.help = "Enter pick/command  u undo  w save  o open by name  Esc back"

    def files(self): return [k for k in self.host.keys() if k.endswith(".wav.b64")]

    def _load(self, key):
        return read_wav(load_b64(self.host, key))

    def render(self, w, h):
        if self.w is None:
            fs = self.files(); self.nav.resize(len(fs))
            out = ["", "  WAV files in the vault (16-bit PCM, mono or stereo):"]
            out += [("  > " if i == self.nav.sel else "    ") + k for i, k in enumerate(fs[:h - 6])]
            if not fs:
                out += ["    (none: export from Music Studio or Sound Synthesizer, or put a name.wav.b64 key in the vault)"]
            return out + ["", "  " + self.msg]
        d, step = self.w.data, max(1, len(self.w.data) // 60)
        env = "".join(" .:-=+*#%@"[min(9, max(abs(v) for v in d[i:i + step]) * 10 // 32768)] for i in range(0, len(d), step))[:70]
        peak = max(abs(v) for v in d)
        return ["", f"  {self.name}", f"  {self.w.rate} Hz  {'stereo' if self.w.ch == 2 else 'mono'}  {self.w.frames} frames  "
                f"{self.w.frames / self.w.rate:.3f} s  peak {peak}/32768", "", "  [" + env + "]", "",
                "  Enter: trim S [E] | gain DB | fadein S | fadeout S | normalize | reverse | mono | concat KEY",
                "  Cannot play: this device has no audio output.", "", "  " + self.msg]

    def key(self, k):
        self.msg = ""
        if self.w is None:
            if self.nav.key(k): return
            if k == "enter" and self.files(): self._open(self.files()[self.nav.sel])
            elif k == "o": return ("push", Prompt("Open", "Vault key of a WAV (name.wav.b64):", "", self._open))
            elif k == "escape": return ("quit",)
            return
        if k == "enter": return ("push", Prompt("Edit", "command:", "", self._cmd))
        if k == "u" and self.prev: self.w = self.prev.pop(); self.msg = "undone"
        elif k == "w": return ("push", Prompt("Save", "Save as vault key:", "edited.wav.b64", self._save))
        elif k == "o": return ("push", Prompt("Open", "Vault key of a WAV (name.wav.b64):", "", self._open))
        elif k == "escape": self.w = None

    def _open(self, key):
        key = key.strip()
        for cand in (key, key + ".wav.b64"):
            if self.host.get(cand) is not None:
                key = cand; break
        try:
            self.w, self.name, self.prev = self._load(key), key, []
        except ValueError as e:
            self.msg = str(e)

    def _cmd(self, line):
        try:
            new = apply_cmd(self.w, line, self._load)
        except ValueError as e:
            self.msg = str(e); return
        self.prev.append(self.w); del self.prev[:-10]
        self.w, self.msg = new, "done: " + line.strip()[:40]

    def _save(self, name):
        name = re.sub(r"[^A-Za-z0-9._-]", "-", name.strip())[:60] or "edited"
        if not name.endswith(".wav.b64"):
            name += ".wav.b64"
        try:
            save_b64(self.host, name, wav_bytes(self.w)); self.name = name; self.msg = "saved " + name
        except ValueError as e:
            self.msg = str(e)


# ================================================================ Music Library ==
MUSIC = R("music-library", "Music Library", "track",
          "title*; artist*; album; year: number; genre; seconds: number; rating: choice(1|2|3|4|5); playlist; file",
          list_cols=("title", "artist", "album", "rating"), amount="seconds", group="artist",
          blurb="A register of the music you own: tracks, albums, artists, ratings and playlists. It cannot play music.")


def mmss(sec) -> str:
    sec = int(sec); h, r = divmod(sec, 3600)
    return (f"{h}:{r // 60:02d}:{r % 60:02d}" if h else f"{r // 60}:{r % 60:02d}")


def m3u(items: list, playlist: str = "") -> str:
    def one(s): return re.sub(r"[\r\n]+", " ", str(s))
    rows = [r for r in items if not playlist or r.get("playlist", "").lower() == playlist.lower()]
    out = ["#EXTM3U"]
    for r in rows:
        out.append(f"#EXTINF:{int(float(r.get('seconds') or 0))},{one(r.get('artist', ''))} - {one(r.get('title', ''))}")
        out.append(one(r.get("file") or r.get("title", "")))
    return "\n".join(out) + "\n"


def music_report(items: list) -> list:
    secs = [float(r.get("seconds") or 0) for r in items]
    rated = [int(r["rating"]) for r in items if r.get("rating")]
    pls: dict = {}
    for r in items:
        if r.get("playlist"):
            pls.setdefault(r["playlist"], []).append(float(r.get("seconds") or 0))
    out = [f"Tracks: {len(items)}", f"Artists: {len({r.get('artist', '').lower() for r in items if r.get('artist')})}",
           f"Albums: {len({(r.get('artist', '').lower(), r.get('album', '').lower()) for r in items if r.get('album')})}",
           f"Total time: {mmss(sum(secs))}", "Average rating: " + (f"{sum(rated) / len(rated):.2f} ({len(rated)} rated)" if rated else "-"), ""]
    out += ["Playlists:"] + [f"  {n}: {len(v)} track(s), {mmss(sum(v))}" for n, v in sorted(pls.items())] if pls else ["No playlists yet."]
    return out


class Library(RecordList):
    def __init__(self, host):
        super().__init__(Data(SpaceHost(host, "music"), MUSIC))
        self.host = host
        self.spec.report, self.spec.report_label = music_report, "Library totals"
        self.help += "  m M3U playlist"

    def key(self, k):
        if k == "m":
            return ("push", Prompt("M3U", "Playlist name (empty = every track shown):", "", self._m3u))
        return super().key(k)

    def _m3u(self, name):
        text = m3u(self.data.items, name.strip())
        self.host.put("playlist.m3u", text)
        self.msg = "wrote vault key 'playlist.m3u'"
        return ("push", TextView("playlist.m3u", text.split("\n")))


# ============================================================ feeds (RSS/Atom) ==
_BAD = re.compile(r"[^\t\n\x20-퟿-�\U00010000-\U0010ffff]")
_TAG = re.compile(r"<[^>]*>")
_DOCTYPE = re.compile(r"<!\s*(doctype|entity)", re.I)


def clean(s, n=2000) -> str:
    return _BAD.sub("", s or "")[:n]


def local(tag) -> str:
    return tag.rsplit("}", 1)[-1].lower() if isinstance(tag, str) else ""


def parse_feed(text: str) -> dict:
    """RSS 2.0 / RSS 1.0 / Atom text -> {"title","link","description","items":[...]}. Never fetches anything."""
    if not isinstance(text, str) or not text.strip():
        raise ValueError("empty feed")
    if len(text) > MAXFEED:
        raise ValueError(f"feed too large (limit {MAXFEED} characters)")
    if _DOCTYPE.search(text):
        raise ValueError("refused: a DOCTYPE or ENTITY declaration is not allowed (entity-expansion attacks)")
    try:
        root = ET.fromstring(text.strip().encode("utf-8"))
    except ET.ParseError as e:
        raise ValueError(f"not well-formed XML: {e}")
    except (ValueError, RecursionError):
        raise ValueError("cannot read this XML")
    if local(root.tag) not in ("rss", "feed", "rdf"):
        raise ValueError("not an RSS or Atom feed")

    def kid(el, *names):
        for c in el:
            if local(c.tag) in names:
                return c

    def txt(el, *names):
        c = kid(el, *names)
        return clean(unescape(_TAG.sub("", "".join(c.itertext())))).strip() if c is not None else ""

    def link(el):
        for c in el:
            if local(c.tag) == "link":
                if c.get("href") and c.get("rel", "alternate") == "alternate": return clean(c.get("href"), 500)
                if c.text and c.text.strip(): return clean(c.text.strip(), 500)
        return ""

    head = kid(root, "channel") if local(root.tag) in ("rss",) else root
    head = head if head is not None else root
    out = {"title": txt(head, "title")[:200], "link": link(head), "description": txt(head, "description", "subtitle")[:500], "items": []}
    for el in root.iter():
        if local(el.tag) not in ("item", "entry"):
            continue
        if len(out["items"]) >= 200:
            break
        enc = ""
        for c in el:
            if local(c.tag) == "enclosure" and c.get("url"): enc = clean(c.get("url"), 500)
            if local(c.tag) == "link" and c.get("rel") == "enclosure" and c.get("href"): enc = clean(c.get("href"), 500)
        out["items"].append({"title": txt(el, "title")[:300] or "(no title)", "link": link(el),
                             "guid": txt(el, "guid", "id")[:500], "date": txt(el, "pubdate", "published", "updated", "date")[:40],
                             "summary": txt(el, "description", "summary", "encoded", "content")[:2000], "enclosure": enc})
    return out


def paste_editor(title: str, handler):
    """Editor for pasted text; Ctrl-G runs handler(text) -> action, or raises ValueError (shown, editor stays)."""
    def go(ed):
        try:
            return handler(ed.area.text)
        except ValueError as e:
            return ("push", Message("Cannot read this", [str(e)]))
    return Editor(title, "", extra_keys={"ctrl-g": go}, hint="paste text, then Ctrl-G")


# ============================================================== Podcast Manager ==
EPISODES = R("podcast-episodes", "Episodes", "episode",
             "title*; date: date; audio_url: url; bytes: number; seconds: number; mime=audio/mpeg; summary",
             list_cols=("title", "date", "seconds"), blurb="Episodes of your show. Each needs an audio_url (where the file is hosted) to enter the feed.")
SUBS = R("podcast-subs", "Subscriptions", "subscription",
         "title*; feed_url: url; category; status: choice(active|paused)=active; notes",
         status="status", list_cols=("title", "category", "status"), blurb="A register of podcasts you follow. It does not download or play anything.")
SHOW_KEYS = ("title", "link", "description", "language", "author")
_DAYS, _MONS = "Mon Tue Wed Thu Fri Sat Sun".split(), "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()


def rfc822(d: str) -> str:
    import datetime
    x = datetime.date.fromisoformat(d)
    return f"{_DAYS[x.weekday()]}, {x.day:02d} {_MONS[x.month - 1]} {x.year} 00:00:00 GMT"


def make_rss(show: dict, episodes: list) -> tuple:
    """-> (xml text, number of episodes left out for lacking an audio_url)."""
    miss = [k for k in ("title", "link", "description") if not str(show.get(k, "")).strip()]
    if miss:
        raise ValueError("show details missing: " + ", ".join(miss))
    if not re.match(r"^https?://\S+$", show["link"].strip()):
        raise ValueError("show link must start with http:// or https://")
    def e(s, n=4000): return escape(clean(str(s), n))
    ep = [x for x in episodes if re.match(r"^https?://\S+$", str(x.get("audio_url", "")))]
    ep = sorted(ep, key=lambda x: x.get("date", ""), reverse=True)[:200]
    out = ['<?xml version="1.0" encoding="UTF-8"?>',
           '<rss version="2.0" xmlns:itunes="http://www.itunes.com/dtds/podcast-1.0.dtd">', "<channel>",
           f"<title>{e(show['title'], 200)}</title>", f"<link>{e(show['link'], 500)}</link>",
           f"<description>{e(show['description'])}</description>", f"<language>{e(show.get('language') or 'en', 20)}</language>"]
    if show.get("author"):
        out.append(f"<itunes:author>{e(show['author'], 200)}</itunes:author>")
    for x in ep:
        it = ["<item>", f"<title>{e(x.get('title', ''), 300)}</title>"]
        if x.get("summary"): it.append(f"<description>{e(x['summary'])}</description>")
        if x.get("date"): it.append(f"<pubDate>{rfc822(x['date'])}</pubDate>")
        it.append(f"<enclosure url={quoteattr(clean(x['audio_url'], 500))} length={quoteattr(str(int(float(x.get('bytes') or 0))))} "
                  f"type={quoteattr(clean(x.get('mime') or 'audio/mpeg', 60))}/>")
        it.append(f"<guid isPermaLink=\"false\">{e(x['audio_url'], 500)}</guid>")
        if x.get("seconds"): it.append(f"<itunes:duration>{int(float(x['seconds']))}</itunes:duration>")
        out += it + ["</item>"]
    out += ["</channel>", "</rss>"]
    xml = "\n".join(out) + "\n"
    if len(xml) > 390_000:
        raise ValueError("feed too large for the vault; shorten the summaries")
    return xml, len(episodes) - len(ep)


def make_podcast(host, entry) -> Screen:
    st = Store(host)

    def show_edit():
        s = st.load("show", {}) or {}
        text = "\n".join(f"{k}: {s.get(k, '')}" for k in SHOW_KEYS)
        def save(t):
            d = {}
            for line in t.split("\n"):
                k, _, v = line.partition(":")
                if k.strip().lower() in SHOW_KEYS: d[k.strip().lower()] = clean(v.strip(), 500)
            st.save("show", d)
        return ("push", Editor("Show details", text, on_save=save, hint="title / link / description / language / author"))

    def generate():
        try:
            xml, skipped = make_rss(st.load("show", {}) or {}, Data(host, EPISODES, "episodes").items)
        except ValueError as e:
            return ("push", Message("Cannot build the feed", [str(e)]))
        host.put("feed.xml", xml)
        return ("push", TextView("feed.xml" + (f" ({skipped} episode(s) without audio_url left out)" if skipped else ""), xml.split("\n")))

    def parsed(text):
        f = parse_feed(text)
        lines = [f"{f['title'] or '(untitled)'}", f["link"], *wrap(f["description"], 74), f"{len(f['items'])} episode(s):", ""]
        for i in f["items"][:100]:
            lines.append(f"  {i['date'][:16]:<16} {i['title'][:50]}" + ("  [audio]" if i["enclosure"] else ""))
        lines += ["", "To follow it, add it under Subscriptions. Nothing is downloaded."]
        return ("replace", TextView("Parsed feed", lines))

    return Menu("Podcast Manager", [
        ("Episodes", lambda: ("push", RecordList(Data(host, EPISODES, "episodes")))),
        ("Subscriptions", lambda: ("push", RecordList(Data(host, SUBS, "subs")))),
        ("Show details", show_edit), ("Generate RSS feed (feed.xml)", generate),
        ("Read a pasted feed", lambda: ("push", paste_editor("Paste an RSS or Atom feed", parsed)))],
        intro=["  Publish a podcast feed you author; keep a list of podcasts you follow.", "  Cannot download or play episodes."])


# ================================================================= News Reader ==
class News:
    MAXITEMS, MAXFEEDS = 2000, 50

    def __init__(self, host):
        self.st = Store(host)
        d = self.st.load("news")
        d = d if isinstance(d, dict) else {}
        self.d = {"next": d.get("next", 1), "feeds": list(d.get("feeds", [])), "items": list(d.get("items", []))}
        self.error = ""

    def save(self):
        self.error = "" if self.st.save("news", self.d) else (getattr(self.st.host, "error", "") or "could not save")

    def add(self, text: str) -> tuple:
        f = parse_feed(text)
        name = f["title"] or "(untitled feed)"
        if name not in self.d["feeds"]:
            if len(self.d["feeds"]) >= self.MAXFEEDS:
                raise ValueError(f"at most {self.MAXFEEDS} feeds")
            self.d["feeds"].append(name)
        have = {(i["feed"], i["key"]) for i in self.d["items"]}
        new = 0
        for it in reversed(f["items"]):               # feeds list newest first; later ids sort first
            key = it["guid"] or it["link"] or it["title"]
            if (name, key) in have:
                continue
            self.d["items"].append({"id": self.d["next"], "feed": name, "key": key, "title": it["title"], "link": it["link"],
                                    "date": it["date"], "summary": it["summary"], "read": False, "star": False})
            self.d["next"] += 1; new += 1
        its = self.d["items"]
        while len(its) > self.MAXITEMS:
            its.remove(next((i for i in its if i["read"] and not i["star"]), None) or next((i for i in its if not i["star"]), its[0]))
        self.save()
        return name, new

    def rows(self, view="all", feed=None, query="") -> list:
        q = query.lower()
        return [i for i in sorted(self.d["items"], key=lambda i: -i["id"])
                if (view == "all" or (view == "unread" and not i["read"]) or (view == "starred" and i["star"]))
                and (feed is None or i["feed"] == feed) and (not q or q in (i["title"] + " " + i["summary"] + " " + i["feed"]).lower())]


class Reader(Screen):
    title = "News Reader"

    def __init__(self, host):
        self.n, self.view, self.feed, self.query, self.msg = News(host), "all", None, "", ""
        self.nav = ListNav(0)
        self.help = "Enter read  m read/unread  s star  v view  f feed  / search  a add feed  r mark all read  D drop feed"

    def render(self, w, h):
        rows = self.n.rows(self.view, self.feed, self.query)
        self.nav.resize(len(rows))
        unread = sum(1 for i in self.n.d["items"] if not i["read"])
        out = [f" view={self.view}  feed={self.feed or 'all'}" + (f"  search='{self.query}'" if self.query else "")
               + f"   {len(rows)} shown, {unread} unread of {len(self.n.d['items'])}"]
        if not self.n.d["items"]:
            out += ["", "  Press a, paste an RSS or Atom feed, then Ctrl-G. Nothing is fetched: this app has no network."]
        top, end = self.nav.window(h - 5)
        t = table([[("*" if i["star"] else " ") + ("" if i["read"] else "N"), i["feed"], i["title"]] for i in rows[top:end]], ["", "Feed", "Title"], maxw=w - 4)
        out += [t[0], t[1]] + [("> " if top + j == self.nav.sel else "  ") + l for j, l in enumerate(t[2:])]
        if self.n.error: out += ["", " ! NOT SAVED: " + self.n.error]
        return out + (["", " " + self.msg] if self.msg else [])

    def cur(self):
        rows = self.n.rows(self.view, self.feed, self.query)
        return rows[self.nav.sel] if rows else None

    def key(self, k):
        self.msg = ""
        if self.nav.key(k): return
        c = self.cur()
        if k == "enter" and c:
            c["read"] = True; self.n.save()
            return ("push", TextView(c["title"][:40], [c["title"], f"{c['feed']}   {c['date']}", c["link"], "", *wrap(c["summary"], 76)]))
        if k == "m" and c: c["read"] = not c["read"]; self.n.save()
        elif k == "s" and c: c["star"] = not c["star"]; self.n.save()
        elif k == "v": self.view = {"all": "unread", "unread": "starred", "starred": "all"}[self.view]
        elif k == "f":
            fs = [None, *self.n.d["feeds"]]
            self.feed = fs[(fs.index(self.feed) + 1) % len(fs)] if self.feed in fs else None
        elif k == "/": return ("push", Prompt("Search", "Search for (empty clears):", self.query, lambda v: setattr(self, "query", v.strip())))
        elif k == "a": return ("push", paste_editor("Paste an RSS or Atom feed", self._add))
        elif k == "r":
            for i in self.n.rows(self.view, self.feed, self.query): i["read"] = True
            self.n.save(); self.msg = "marked read"
        elif k == "D" and c:
            return ("push", Confirm(f"Remove feed '{c['feed']}' and its articles?", lambda: self._drop(c["feed"])))
        elif k == "escape":
            if self.query or self.feed or self.view != "all": self.query, self.feed, self.view = "", None, "all"
            else: return ("quit",)

    def _add(self, text):
        name, new = self.n.add(text)
        self.msg = f"{name}: {new} new article(s)"
        return ("pop", None)

    def _drop(self, feed):
        self.n.d["feeds"] = [f for f in self.n.d["feeds"] if f != feed]
        self.n.d["items"] = [i for i in self.n.d["items"] if i["feed"] != feed]
        self.feed = None; self.n.save(); self.msg = "feed removed"


# ==================================================================== ENTRIES ==
ENTRIES: list = [
    app("Music Studio", lambda h, e: workshop(h, "Music Studio", "score", SCORE_EXAMPLE, SCORE_HELP, build_score, "song.wav.b64, song.mid.b64", register_song(h)),
        "partial", uses=["music"], note="Writes a text score and exports a real WAV (sine mix) and a type 1 MIDI file. Monophonic tracks, no chords or "
                   "dynamics. Cannot play or record sound: KOS has no audio device."),
    app("Sound Synthesizer", lambda h, e: workshop(h, "Sound Synthesizer", "patch", SYNTH_EXAMPLE, SYNTH_HELP, build_patch, "synth.wav.b64"),
        "partial", note="Oscillators, noise, ADSR and tremolo mixed to a short mono WAV (max 10 s, 4-22 kHz, size capped). "
                   "No filters or keyboard, and it cannot play the result: KOS has no audio device."),
    app("Audio Editor", lambda h, e: AudioEditor(h), "partial",
        "Edits 16-bit PCM WAV files already in the vault: trim, gain, fades, normalize, reverse, mono, concat. Whole-file "
        "commands only, size capped (about 18 s at 8 kHz); cannot play audio (no audio device)."),
    app("Music Library", lambda h, e: Library(h), "partial", owns=["music"], note="A register of tracks, albums, artists, ratings and playlists with totals and M3U export. It only lists your music: "
        "it cannot play it, scan files or fetch artwork (no audio device, no network)."),
    app("Podcast Manager", make_podcast, "partial",
        "Keeps episodes and a subscription register, writes a valid RSS 2.0 feed (all text escaped) and reads a feed you paste. "
        "It cannot download, play or host episodes or fetch feeds: KOS has no network or audio."),
    app("News Reader", lambda h, e: Reader(h), "partial",
        "Reads RSS and Atom text you paste (DOCTYPE/ENTITY refused, size capped): read/unread, stars, search, per-feed lists. "
        "It cannot fetch or refresh feeds: KOS has no network, so you paste each update."),
]

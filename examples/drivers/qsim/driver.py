"""qsim: a quantum *emulator* that speaks the KOS quantum driver protocol.

A real driver would open its device node and translate the job into the hardware's own commands; this one multiplies a state
vector. It is here so the whole path (job in, counts out, sandboxed, with a password) can be exercised without hardware, and so
an app written against the protocol runs the same on either. Its result says ``"emulated": true`` - always.

Supported OpenQASM-lite: ``OPENQASM 2.0/3.0;`` and ``include`` lines are ignored; ``qreg q[n];`` / ``qubit[n] q;``;
``creg c[n];`` / ``bit[n] c;``; gates h x y z s sdg t tdg sx rx(a) ry(a) rz(a) p(a) cx cz swap ccx;
``measure q[i] -> c[j];`` and ``measure q -> c;``. Angles may be numbers, ``pi``, ``pi/2``, ``-pi/4`` ...
"""

import cmath
import json
import math
import random
import re

from kos.sdk import App

MAX_QUBITS = 14
SQ2 = 1 / math.sqrt(2)


def _angle(text):
    t = text.strip().replace("pi", repr(math.pi))
    if not re.fullmatch(r"[0-9eE+\-*/(). ]+", t):
        raise ValueError(f"bad angle {text!r}")
    return float(eval(t, {"__builtins__": {}}, {}))      # digits and operators only, checked above


def _gate_1q(name, a=None):
    I = 1j
    if name == "h":
        return [[SQ2, SQ2], [SQ2, -SQ2]]
    if name == "x":
        return [[0, 1], [1, 0]]
    if name == "y":
        return [[0, -I], [I, 0]]
    if name == "z":
        return [[1, 0], [0, -1]]
    if name == "s":
        return [[1, 0], [0, I]]
    if name == "sdg":
        return [[1, 0], [0, -I]]
    if name == "t":
        return [[1, 0], [0, cmath.exp(I * math.pi / 4)]]
    if name == "tdg":
        return [[1, 0], [0, cmath.exp(-I * math.pi / 4)]]
    if name == "sx":
        return [[(1 + I) / 2, (1 - I) / 2], [(1 - I) / 2, (1 + I) / 2]]
    if name == "rx":
        return [[math.cos(a / 2), -I * math.sin(a / 2)], [-I * math.sin(a / 2), math.cos(a / 2)]]
    if name == "ry":
        return [[math.cos(a / 2), -math.sin(a / 2)], [math.sin(a / 2), math.cos(a / 2)]]
    if name in ("rz", "p"):
        return [[cmath.exp(-I * a / 2) if name == "rz" else 1, 0], [0, cmath.exp(I * a / 2) if name == "rz" else cmath.exp(I * a)]]
    raise ValueError(f"unknown gate {name}")


class Circuit:
    def __init__(self):
        self.n = 0
        self.cbits = 0
        self.ops = []          # ("gate", name, angle, qubits) | ("measure", q, c)
        self.qreg = {}
        self.creg = {}

    def parse(self, text):
        for raw in text.replace("\r", "").replace(";", ";\n").split("\n"):
            line = raw.split("//")[0].strip().rstrip(";").strip()
            if not line or line.upper().startswith(("OPENQASM", "INCLUDE")):
                continue
            m = re.fullmatch(r"qreg\s+(\w+)\[(\d+)\]", line) or re.fullmatch(r"qubit\[(\d+)\]\s+(\w+)", line)
            if m:
                a, b = (m.group(1), int(m.group(2))) if line.startswith("qreg") else (m.group(2), int(m.group(1)))
                self.qreg[a] = (self.n, b)
                self.n += b
                continue
            m = re.fullmatch(r"creg\s+(\w+)\[(\d+)\]", line) or re.fullmatch(r"bit\[(\d+)\]\s+(\w+)", line)
            if m:
                a, b = (m.group(1), int(m.group(2))) if line.startswith("creg") else (m.group(2), int(m.group(1)))
                self.creg[a] = (self.cbits, b)
                self.cbits += b
                continue
            m = re.fullmatch(r"measure\s+(\w+)(?:\[(\d+)\])?\s*->\s*(\w+)(?:\[(\d+)\])?", line)
            m3 = re.fullmatch(r"(\w+)(?:\[(\d+)\])?\s*=\s*measure\s+(\w+)(?:\[(\d+)\])?", line)      # OpenQASM 3: c = measure q
            if m or m3:
                qr, qi, cr, ci = m.groups() if m else (m3.group(3), m3.group(4), m3.group(1), m3.group(2))
                qs = self._regidx(self.qreg, qr, qi)
                cs = self._regidx(self.creg, cr, ci)
                if len(qs) != len(cs):
                    raise ValueError("measure needs registers of equal size")
                self.ops += [("measure", q, c) for q, c in zip(qs, cs)]
                continue
            m = re.fullmatch(r"(\w+)(?:\(([^)]*)\))?\s+(.+)", line)
            if not m:
                raise ValueError(f"cannot read: {line!r}")
            name, ang, args = m.group(1).lower(), m.group(2), m.group(3)
            qs = []
            for a in args.split(","):
                ref = re.fullmatch(r"(\w+)(?:\[(\d+)\])?", a.strip())
                if not ref:
                    raise ValueError(f"cannot read the qubit {a.strip()!r}")
                qs.append(self._regidx(self.qreg, *ref.groups())[0])
            self.ops.append(("gate", name, _angle(ang) if ang else None, qs))
        if not 1 <= self.n <= MAX_QUBITS:
            raise ValueError(f"1 to {MAX_QUBITS} qubits")

    @staticmethod
    def _regidx(reg, name, idx):
        if name not in reg:
            raise ValueError(f"unknown register {name}")
        base, size = reg[name]
        if idx is None:
            return list(range(base, base + size))
        if int(idx) >= size:
            raise ValueError(f"{name}[{idx}] is out of range")
        return [base + int(idx)]


class State:
    def __init__(self, n):
        self.n = n
        self.amp = [0j] * (1 << n)
        self.amp[0] = 1 + 0j

    def apply_1q(self, u, q):
        step, size = 1 << q, 1 << self.n
        a = self.amp
        for base in range(0, size, step << 1):
            for i in range(base, base + step):
                x, y = a[i], a[i + step]
                a[i], a[i + step] = u[0][0] * x + u[0][1] * y, u[1][0] * x + u[1][1] * y

    def apply_controlled(self, u, controls, target):
        mask = sum(1 << c for c in controls)
        step, a = 1 << target, self.amp
        for i in range(1 << self.n):
            if i & step == 0 and (i & mask) == mask:
                x, y = a[i], a[i + step]
                a[i], a[i + step] = u[0][0] * x + u[0][1] * y, u[1][0] * x + u[1][1] * y

    def swap(self, p, q):
        a = self.amp
        for i in range(1 << self.n):
            if (i >> p) & 1 != (i >> q) & 1 and (i >> p) & 1 == 0:
                j = i ^ (1 << p) ^ (1 << q)
                a[i], a[j] = a[j], a[i]

    def probabilities(self):
        return [abs(x) ** 2 for x in self.amp]


def run(program, shots, seed=None):
    circ = Circuit()
    circ.parse(program)
    state = State(circ.n)
    measures = []
    for op in circ.ops:
        if op[0] == "measure":
            measures.append((op[1], op[2]))
            continue
        _, name, ang, qs = op
        if measures:
            raise ValueError("gates after a measurement are not supported (measure at the end)")
        if name in ("cx", "cnot"):
            state.apply_controlled(_gate_1q("x"), [qs[0]], qs[1])
        elif name == "cz":
            state.apply_controlled(_gate_1q("z"), [qs[0]], qs[1])
        elif name == "ccx":
            state.apply_controlled(_gate_1q("x"), qs[:2], qs[2])
        elif name == "swap":
            state.swap(qs[0], qs[1])
        else:
            if len(qs) != 1:
                raise ValueError(f"{name} takes one qubit")
            state.apply_1q(_gate_1q(name, ang), qs[0])
    if not measures:
        measures = [(q, q) for q in range(circ.n)]
        circ.cbits = circ.n
    rng = random.Random(seed)
    probs = state.probabilities()
    outcomes = rng.choices(range(len(probs)), weights=probs, k=shots)
    counts = {}
    for o in outcomes:
        bits = ["0"] * circ.cbits
        for q, c in measures:
            bits[c] = str((o >> q) & 1)
        key = "".join(reversed(bits))                         # classical bit 0 on the right, like OpenQASM tools print
        counts[key] = counts.get(key, 0) + 1
    return {"counts": dict(sorted(counts.items())), "shots": shots, "qubits": circ.n, "emulated": True,
            "device": "qsim emulator (state vector)"}


def main():
    app = App()
    for ev in app.events():
        if ev.get("cmd") != "launch" or ev.get("command") != "job":
            continue
        try:
            job = json.loads(ev.get("line") or "{}")
            res = run(job["program"], int(job.get("shots", 1024)), job.get("seed"))
        except Exception as e:                                   # a bad circuit is an answer, not a crash
            res = {"error": str(e)[:300], "emulated": True}
        app.log("RESULT " + json.dumps(res))
        app.exit(0)
        break

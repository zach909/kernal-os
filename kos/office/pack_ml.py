"""pack_ml: Machine Learning Lab - classical machine learning on a small pasted CSV table.

Plain stdlib Python, seeded and deterministic, with hard caps on rows, columns, epochs and total work so
nothing can hang or exhaust memory. Nothing runs in the background."""

from __future__ import annotations

import json
import math
import random

from .packkit import app
from .ui import Editor, Menu, Message, Prompt, Screen, Store, TextView, bar, table, wrap  # noqa: F401

MAX_ROWS, MAX_COLS, MAX_CHARS, MAX_CLASSES = 500, 12, 20000, 20
MAX_WORK = 6_000_000          # rough multiply-add budget for the iterative trainers
ALGOS = ["linreg", "logistic", "knn", "kmeans", "tree", "nb", "mlp"]
NAMES = {"linreg": "Linear regression (normal equations)", "logistic": "Logistic regression (gradient descent)",
         "knn": "k-nearest neighbours", "kmeans": "k-means (k-means++ seeding)",
         "tree": "Decision tree (CART, gini)", "nb": "Gaussian naive Bayes", "mlp": "Multilayer perceptron (backprop)"}
PARAM = {"logistic": ("epochs", 400, 1, 2000), "knn": ("k", 3, 1, 25), "kmeans": ("k", 3, 1, 12),
         "tree": ("max depth", 4, 1, 8), "mlp": ("epochs", 1500, 1, 3000)}
CLASSIFIERS = ("logistic", "knn", "tree", "nb", "mlp")


class MLError(ValueError):
    pass


# ------------------------------------------------------------------ data ----
def num(s):
    try:
        v = float(s)
    except ValueError:
        return None
    return v if math.isfinite(v) and abs(v) < 1e12 else None


def parse(text):
    """CSV text -> (header or None, rows of floats). Last column is the target. Refuses anything odd."""
    if not isinstance(text, str) or len(text) > MAX_CHARS:
        raise MLError(f"data too large (limit {MAX_CHARS} characters)")
    if any(ord(c) < 32 and c not in "\n\r\t" for c in text):
        raise MLError("control characters in data")
    lines = [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]
    if len(lines) > MAX_ROWS + 1:
        raise MLError(f"too many rows (limit {MAX_ROWS})")
    grid = [[c.strip() for c in (l.split(",") if "," in l else l.split())] for l in lines]
    if not grid:
        raise MLError("no data")
    header = None
    if all(num(c) is None for c in grid[0]):
        header, grid = grid[0], grid[1:]
    if len(grid) < 2:
        raise MLError("need at least 2 data rows")
    w = len(grid[0])
    if not 2 <= w <= MAX_COLS:
        raise MLError(f"need 2 to {MAX_COLS} columns (features then target)")
    if header is not None and len(header) != w:
        raise MLError("header has a different width from the data")
    rows = []
    for n, r in enumerate(grid, 1):
        if len(r) != w:
            raise MLError(f"ragged row {n}: {len(r)} cells, expected {w}")
        vals = [num(c) for c in r]
        if None in vals:
            raise MLError(f"non-numeric or non-finite value in row {n}")
        rows.append(vals)
    return header, rows


def split(rows, test_pct, seed):
    idx = list(range(len(rows)))
    random.Random(seed).shuffle(idx)
    nt = min(len(rows) - 1, int(len(rows) * max(0, min(50, test_pct)) / 100))
    return [rows[i] for i in idx[nt:]], [rows[i] for i in idx[:nt]]


def stats(X):
    d, n = len(X[0]), len(X)
    mean = [sum(r[j] for r in X) / n for j in range(d)]
    sd = [math.sqrt(sum((r[j] - mean[j]) ** 2 for r in X) / n) or 1.0 for j in range(d)]
    return mean, sd


def scale(X, mean, sd):
    return [[(v - m) / s for v, m, s in zip(r, mean, sd)] for r in X]


# --------------------------------------------------------------- metrics ----
def metrics_cls(actual, pred, classes):
    k = len(classes)
    pos = {c: i for i, c in enumerate(classes)}
    cm = [[0] * k for _ in range(k)]                     # rows = actual, columns = predicted
    for a, p in zip(actual, pred):
        cm[pos[a]][pos[p]] += 1
    per = []
    for i in range(k):
        tp = cm[i][i]
        pp, ap = sum(cm[r][i] for r in range(k)), sum(cm[i])
        pr, rc = (tp / pp if pp else 0.0), (tp / ap if ap else 0.0)
        per.append((pr, rc, 2 * pr * rc / (pr + rc) if pr + rc else 0.0))
    acc = sum(cm[i][i] for i in range(k)) / max(1, len(actual))
    return {"accuracy": acc, "confusion": cm, "per_class": per, "macro_f1": sum(f for _, _, f in per) / k}


def metrics_reg(actual, pred):
    n = max(1, len(actual))
    ss_res = sum((a - p) ** 2 for a, p in zip(actual, pred))
    m = sum(actual) / n
    ss_tot = sum((a - m) ** 2 for a in actual)
    return {"rmse": math.sqrt(ss_res / n), "r2": (1 - ss_res / ss_tot) if ss_tot else (1.0 if ss_res < 1e-18 else 0.0)}


# ------------------------------------------------------------- algorithms ----
def solve(A, b):
    """Gauss-Jordan with partial pivoting."""
    n = len(A)
    M = [list(A[i]) + [b[i]] for i in range(n)]
    scale_ = max(abs(v) for r in A for v in r) or 1.0
    for c in range(n):
        p = max(range(c, n), key=lambda r: abs(M[r][c]))
        if abs(M[p][c]) < 1e-10 * scale_:
            raise MLError("singular system: features are collinear or constant")
        M[c], M[p] = M[p], M[c]
        piv = M[c][c]
        M[c] = [v / piv for v in M[c]]
        for r in range(n):
            if r != c and M[r][c]:
                f = M[r][c]
                M[r] = [a - f * b_ for a, b_ in zip(M[r], M[c])]
    return [M[i][n] for i in range(n)]


def fit_linreg(X, y):
    """Normal equations (X'X) w = X'y with a bias column. Returns [bias, w1, ...]."""
    A = [[1.0] + list(r) for r in X]
    d = len(A[0])
    if len(A) < d:
        raise MLError("need at least as many rows as coefficients")
    xtx = [[sum(r[i] * r[j] for r in A) for j in range(d)] for i in range(d)]
    xty = [sum(r[i] * t for r, t in zip(A, y)) for i in range(d)]
    return solve(xtx, xty)


def sigmoid(z):
    return 1 / (1 + math.exp(-z)) if z >= 0 else math.exp(z) / (1 + math.exp(z))


def fit_logistic(X, y, epochs, lr=0.5):
    n, d = len(X), len(X[0])
    w, b, loss = [0.0] * d, 0.0, []
    for _ in range(epochs):
        gw, gb, L = [0.0] * d, 0.0, 0.0
        for r, t in zip(X, y):
            p = sigmoid(sum(a * c for a, c in zip(w, r)) + b)
            e = p - t
            gb += e
            for j in range(d):
                gw[j] += e * r[j]
            L -= math.log(max(p if t else 1 - p, 1e-12))
        w = [a - lr * g / n for a, g in zip(w, gw)]
        b -= lr * gb / n
        loss.append(L / n)
    return w, b, loss


def kmeans(X, k, seed, iters=50):
    rng = random.Random(seed)
    k = min(k, len(X))
    cen = [list(X[rng.randrange(len(X))])]
    while len(cen) < k:                                  # k-means++: pick by squared distance
        d2 = [min(sum((a - b) ** 2 for a, b in zip(r, c)) for c in cen) for r in X]
        tot, pick = sum(d2), rng.random() * sum(d2)
        i = 0
        if tot > 0:
            acc = 0.0
            for i, v in enumerate(d2):
                acc += v
                if acc >= pick and v > 0:
                    break
        else:
            i = rng.randrange(len(X))
        cen.append(list(X[i]))
    lab, hist = [-1] * len(X), []
    for _ in range(iters):
        new = [min(range(k), key=lambda c: sum((a - b) ** 2 for a, b in zip(r, cen[c]))) for r in X]
        hist.append(sum(sum((a - b) ** 2 for a, b in zip(r, cen[c])) for r, c in zip(X, new)))
        if new == lab:
            break
        lab = new
        for c in range(k):
            mem = [r for r, l in zip(X, lab) if l == c]
            if mem:
                cen[c] = [sum(r[j] for r in mem) / len(mem) for j in range(len(X[0]))]
    return cen, lab, hist


def gini(counts, n):
    return 1 - sum((c / n) ** 2 for c in counts) if n else 0.0


def build_tree(X, y, k, depth, idx=None):
    idx = list(range(len(X))) if idx is None else idx
    cnt = [0] * k
    for i in idx:
        cnt[y[i]] += 1
    leaf = {"c": cnt.index(max(cnt))}
    base = gini(cnt, len(idx))
    if depth == 0 or base == 0:
        return leaf
    best = None
    for j in range(len(X[0])):
        order = sorted(idx, key=lambda i: X[i][j])
        left, right = [0] * k, cnt[:]
        for p in range(len(order) - 1):
            c = y[order[p]]
            left[c] += 1
            right[c] -= 1
            v, w = X[order[p]][j], X[order[p + 1]][j]
            if v == w:
                continue
            g = ((p + 1) * gini(left, p + 1) + (len(order) - p - 1) * gini(right, len(order) - p - 1)) / len(order)
            if g < base - 1e-12 and (best is None or g < best[0] - 1e-12):
                best = (g, j, (v + w) / 2)
    if best is None:
        return leaf
    _, j, t = best
    lo = [i for i in idx if X[i][j] <= t]
    hi = [i for i in idx if X[i][j] > t]
    return {"f": j, "t": t, "l": build_tree(X, y, k, depth - 1, lo), "r": build_tree(X, y, k, depth - 1, hi)}


def tree_predict(node, x):
    while "c" not in node:
        node = node["l"] if x[node["f"]] <= node["t"] else node["r"]
    return node["c"]


def fit_nb(X, y, k):
    out = []
    for c in range(k):
        rows = [r for r, t in zip(X, y) if t == c]
        n = len(rows)
        mean = [sum(r[j] for r in rows) / n for j in range(len(X[0]))]
        var = [max(sum((r[j] - mean[j]) ** 2 for r in rows) / n, 1e-9) for j in range(len(X[0]))]
        out.append({"prior": n / len(X), "mean": mean, "var": var})
    return out


def nb_predict(m, x):
    def score(c):
        return math.log(c["prior"]) - 0.5 * sum(math.log(2 * math.pi * v) + (a - mu) ** 2 / v
                                                for a, mu, v in zip(x, c["mean"], c["var"]))
    return max(range(len(m)), key=lambda i: score(m[i]))


def softmax(z):
    m = max(z)
    e = [math.exp(v - m) for v in z]
    s = sum(e)
    return [v / s for v in e]


def mlp_forward(m, x):
    h = [math.tanh(sum(w * a for w, a in zip(row, x)) + b) for row, b in zip(m["W1"], m["b1"])]
    return h, softmax([sum(w * a for w, a in zip(row, h)) + b for row, b in zip(m["W2"], m["b2"])])


def fit_mlp(X, y, k, epochs, seed, hidden=8, lr=0.5):
    rng, d = random.Random(seed), len(X[0])
    u = lambda fan: [rng.uniform(-1, 1) / math.sqrt(fan) for _ in range(fan)]  # noqa: E731
    m = {"W1": [u(d) for _ in range(hidden)], "b1": [0.0] * hidden, "W2": [u(hidden) for _ in range(k)], "b2": [0.0] * k}
    n, loss = len(X), []
    for _ in range(epochs):
        g1 = [[0.0] * d for _ in range(hidden)]
        gb1, g2, gb2, L = [0.0] * hidden, [[0.0] * hidden for _ in range(k)], [0.0] * k, 0.0
        for x, t in zip(X, y):
            h, p = mlp_forward(m, x)
            L -= math.log(max(p[t], 1e-12))
            dz = [p[c] - (c == t) for c in range(k)]
            dh = [sum(dz[c] * m["W2"][c][i] for c in range(k)) * (1 - h[i] ** 2) for i in range(hidden)]
            for c in range(k):
                gb2[c] += dz[c]
                for i in range(hidden):
                    g2[c][i] += dz[c] * h[i]
            for i in range(hidden):
                gb1[i] += dh[i]
                for j in range(d):
                    g1[i][j] += dh[i] * x[j]
        for i in range(hidden):
            m["b1"][i] -= lr * gb1[i] / n
            for j in range(d):
                m["W1"][i][j] -= lr * g1[i][j] / n
        for c in range(k):
            m["b2"][c] -= lr * gb2[c] / n
            for i in range(hidden):
                m["W2"][c][i] -= lr * g2[c][i] / n
        loss.append(L / n)
    return m, loss


# ------------------------------------------------------------ train/predict ----
def train(algo, X, y, p=None, seed=1, std=True):
    """Fit one model. X rows of floats, y floats (labels for classifiers). Returns (model, loss list)."""
    if algo not in ALGOS:
        raise MLError("unknown algorithm")
    if not X or len(X) > MAX_ROWS or len(X[0]) > MAX_COLS - 1 or len(X) != len(y):
        raise MLError("bad table size")
    name, dflt, lo, hi = PARAM.get(algo, ("", 0, 0, 0))
    p = dflt if p is None else max(lo, min(hi, int(p)))
    n, d = len(X), len(X[0])
    model = {"algo": algo, "features": d, "std": None, "seed": seed}
    if std:
        mean, sd = stats(X)
        model["std"] = {"mean": mean, "sd": sd}
        X = scale(X, mean, sd)
    loss = []
    if algo == "linreg":
        model["coef"] = fit_linreg(X, y)
        loss = [sum((model["coef"][0] + sum(c * v for c, v in zip(model["coef"][1:], r)) - t) ** 2 for r, t in zip(X, y)) / n]
        return model, loss
    if algo == "kmeans":
        if n * p * d * 50 > MAX_WORK * 10:
            raise MLError("too much work")
        model["centers"], lab, loss = kmeans(X, p, seed)
        model["labels"], model["inertia"] = lab, loss[-1]
        return model, loss
    classes = sorted(set(y))
    if len(classes) > MAX_CLASSES:
        raise MLError(f"too many classes (limit {MAX_CLASSES})")
    if len(classes) < 2:
        raise MLError("the target column needs at least 2 different values")
    yi = [classes.index(t) for t in y]
    model["classes"] = classes
    if algo == "logistic":
        if len(classes) != 2:
            raise MLError("logistic regression here is binary: the target must have exactly 2 values")
        if p * n * d > MAX_WORK:
            raise MLError("too much work: lower epochs or rows")
        model["w"], model["b"], loss = fit_logistic(X, yi, p)
    elif algo == "knn":
        model["k"], model["X"], model["y"] = min(p, n), X, yi
    elif algo == "tree":
        model["tree"] = build_tree(X, yi, len(classes), p)
    elif algo == "nb":
        model["nb"] = fit_nb(X, yi, len(classes))
    else:
        if p * n * 8 * (d + len(classes)) > MAX_WORK:
            raise MLError("too much work: lower epochs or rows")
        model["net"], loss = fit_mlp(X, yi, len(classes), p, seed)
    return model, loss


def predict(model, X):
    if any(len(r) != model["features"] for r in X):
        raise MLError(f"expected {model['features']} feature values")
    if model["std"]:
        X = scale(X, model["std"]["mean"], model["std"]["sd"])
    a, out = model["algo"], []
    for x in X:
        if a == "linreg":
            out.append(model["coef"][0] + sum(c * v for c, v in zip(model["coef"][1:], x)))
        elif a == "kmeans":
            cen = model["centers"]
            out.append(min(range(len(cen)), key=lambda c: sum((u - v) ** 2 for u, v in zip(x, cen[c]))))
        else:
            if a == "logistic":
                i = int(sigmoid(sum(w * v for w, v in zip(model["w"], x)) + model["b"]) >= 0.5)
            elif a == "knn":
                near = sorted(range(len(model["X"])), key=lambda j: (sum((u - v) ** 2 for u, v in zip(x, model["X"][j])), j))[:model["k"]]
                votes = {}
                for j in near:
                    votes[model["y"][j]] = votes.get(model["y"][j], 0) + 1
                i = min(votes, key=lambda c: (-votes[c], c))
            elif a == "tree":
                i = tree_predict(model["tree"], x)
            elif a == "nb":
                i = nb_predict(model["nb"], x)
            else:
                p = mlp_forward(model["net"], x)[1]
                i = p.index(max(p))
            out.append(model["classes"][i])
    return out


def export(model):
    m = {k: v for k, v in model.items() if k not in ("labels",)}
    return json.dumps(m, separators=(",", ":"), allow_nan=False)


def curve(loss, width=30, rows=20):
    if not loss:
        return ["(this algorithm has no iterative loss)"]
    step = max(1, math.ceil(len(loss) / rows))
    pts = list(range(0, len(loss), step))
    if pts[-1] != len(loss) - 1:
        pts.append(len(loss) - 1)
    top = max(loss) or 1.0
    return [f"{i + 1:>5}  {loss[i]:>10.5f}  {bar(loss[i], top, width)}" for i in pts]


def g(v):
    return f"{v:.6g}"


# ------------------------------------------------------------------- lab ----
def describe(model, names):
    a, out = model["algo"], []
    if a == "linreg":
        out += ["bias " + g(model["coef"][0])] + [f"{n}  {g(c)}" for n, c in zip(names, model["coef"][1:])]
        if model["std"]:
            out.append("(coefficients are on standardised features)")
    elif a == "logistic":
        out += ["bias " + g(model["b"])] + [f"{n}  {g(c)}" for n, c in zip(names, model["w"])]
    elif a == "kmeans":
        sizes = [model["labels"].count(c) for c in range(len(model["centers"]))]
        out += [f"cluster {c}: {sizes[c]} rows  centre " + ", ".join(g(v) for v in cen) for c, cen in enumerate(model["centers"])]
        out.append("inertia " + g(model["inertia"]))
    elif a == "tree":
        def walk(nd, ind):
            if len(out) > 40:
                return
            if "c" in nd:
                out.append("  " * ind + "-> " + g(model["classes"][nd["c"]]))
            else:
                out.append("  " * ind + f"{names[nd['f']]} <= {g(nd['t'])}")
                walk(nd["l"], ind + 1)
                out.append("  " * ind + "else")
                walk(nd["r"], ind + 1)
        walk(model["tree"], 0)
    elif a == "nb":
        out += [f"class {g(c)}: prior {g(m['prior'])}" for c, m in zip(model["classes"], model["nb"])]
    elif a == "knn":
        out.append(f"k = {model['k']} over {len(model['X'])} stored rows")
    else:
        out.append(f"{model['features']} inputs -> {len(model['net']['b1'])} tanh units -> {len(model['classes'])} softmax outputs")
    return out


def evaluate(model, rows, label):
    X, y = [r[:-1] for r in rows], [r[-1] for r in rows]
    pred = predict(model, X)
    if model["algo"] == "linreg":
        m = metrics_reg(y, pred)
        return [f"{label} ({len(rows)} rows): RMSE {g(m['rmse'])}   R^2 {g(m['r2'])}"]
    m = metrics_cls(y, pred, model["classes"])
    cl = [g(c) for c in model["classes"]]
    out = [f"{label} ({len(rows)} rows): accuracy {m['accuracy']:.4f}   macro F1 {m['macro_f1']:.4f}", "confusion (rows actual, cols predicted):"]
    out += ["  " + l for l in table([[c] + r for c, r in zip(cl, m["confusion"])], ["act\\pred"] + cl)]
    out += ["  " + l for l in table([[c] + [f"{v:.3f}" for v in pr] for c, pr in zip(cl, m["per_class"])], ["class", "precision", "recall", "F1"])]
    return out


SAMPLES = [("XOR (neural network demo)", "a,b,y\n0,0,0\n0,1,1\n1,0,1\n1,1,0", 0),
           ("y = 2x + 1 (regression)", "x,y\n1,3\n2,5\n3,7\n4,9\n5,11\n6,13\n7,15\n8,17", 0),
           ("three blobs (classes 0, 1, 2)", "x,y,class\n0,0,0\n1,0,0\n0,1,0\n1,1,0\n10,10,1\n11,10,1\n10,11,1\n11,11,1\n"
            "0,10,2\n1,10,2\n0,11,2\n1,11,2", 0)]


class Lab(Menu):
    title = "Machine Learning Lab"

    def __init__(self, host):
        self.host, self.store = host, Store(host)
        s = self.store.load("ml_state", {}) or {}
        ok = lambda v, lo, hi, d: v if isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi else d  # noqa: E731
        self.data = s.get("data") if isinstance(s.get("data"), str) and len(s["data"]) <= MAX_CHARS else SAMPLES[0][1]
        self.algo = s.get("algo") if s.get("algo") in ALGOS else "mlp"
        self.seed, self.test = ok(s.get("seed"), 0, 10 ** 9, 1), ok(s.get("test"), 0, 50, 25)
        self.std = s.get("std") is not False
        self.ps = {a: ok((s.get("ps") or {}).get(a) if isinstance(s.get("ps"), dict) else None, PARAM[a][2], PARAM[a][3], PARAM[a][1]) for a in PARAM}
        self.model = self.loss = None
        self.names = []
        super().__init__(self.title, [], ["Classical machine learning on a small table (<=500 rows, <=12 columns,",
                                          "last column = target). Seeded and deterministic."])
        self.build()

    def save(self):
        self.store.save("ml_state", {"data": self.data, "algo": self.algo, "seed": self.seed, "test": self.test, "std": self.std, "ps": self.ps})
        self.build()

    def build(self):
        pr = PARAM.get(self.algo)
        e = [("Edit data (paste CSV)", self.edit_data), ("Load sample data", self.samples),
             (f"Algorithm: {NAMES[self.algo]}", self.next_algo)]
        if pr:
            e.append((f"{pr[0].capitalize()}: {self.ps[self.algo]}", self.ask_param))
        e += [(f"Seed: {self.seed}", lambda: self.ask("Seed", "Seed (whole number)", self.seed, "seed", 0, 10 ** 9)),
              (f"Test split: {self.test}%", lambda: self.ask("Test split", "Test percentage 0-50", self.test, "test", 0, 50)),
              (f"Standardise features: {'yes' if self.std else 'no'}", self.toggle_std),
              ("Train and evaluate", self.run_train), ("Predict a new row", self.ask_row),
              ("Loss curve", self.show_curve), ("Export model as JSON", self.show_export)]
        self.entries = e
        self.nav.resize(len(e))

    def on_enter(self):
        self.build()

    def edit_data(self):
        def on_save(t):
            if len(t) > MAX_CHARS:
                return
            self.data = t
            self.save()
        return ("push", Editor("Data (CSV)", self.data, on_save, hint="last column = target"))

    def samples(self):
        def pick(s):
            self.data, self.test = s[1], s[2]
            self.algo = "mlp" if s[0].startswith("XOR") else ("linreg" if s[0].startswith("y =") else "kmeans")
            self.model = None
            self.save()
        return ("push", Menu("Samples", [(s[0], (lambda s=s: ("pop", lambda: pick(s)))) for s in SAMPLES]))

    def next_algo(self):
        self.algo = ALGOS[(ALGOS.index(self.algo) + 1) % len(ALGOS)]
        self.save()

    def toggle_std(self):
        self.std = not self.std
        self.save()

    def ask_param(self):
        n, _, lo, hi = PARAM[self.algo]
        return self.ask(n, f"{n} ({lo}-{hi})", self.ps[self.algo], None, lo, hi)

    def ask(self, title, label, cur, attr, lo, hi):
        def done(t):
            try:
                v = int(t.strip())
            except ValueError:
                return ("push", Message("Not a number", ["Enter a whole number."]))
            v = max(lo, min(hi, v))
            if attr:
                setattr(self, attr, v)
            else:
                self.ps[self.algo] = v
            self.save()
        return ("push", Prompt(title, label, str(cur), done))

    def run_train(self):
        try:
            header, rows = parse(self.data)
            d = len(rows[0]) - 1
            self.names = header[:-1] if header else [f"x{i + 1}" for i in range(d)]
            tr, te = split(rows, self.test, self.seed)
            p = self.ps.get(self.algo)
            if self.algo == "kmeans":
                tr, te = rows, []
            self.model, self.loss = train(self.algo, [r[:-1] for r in tr], [r[-1] for r in tr], p, self.seed, self.std)
            out = [f"{NAMES[self.algo]}: {len(tr)} training rows, {len(te)} test rows, seed {self.seed}", ""]
            out += describe(self.model, self.names) + [""]
            if self.algo != "kmeans":
                out += evaluate(self.model, tr, "train")
                if te:
                    out += [""] + evaluate(self.model, te, "test")
            return ("push", TextView("Report", out))
        except MLError as e:
            return ("push", Message("Cannot train", [str(e)]))

    def ask_row(self):
        if not self.model:
            return ("push", Message("No model", ["Train and evaluate first."]))
        d = self.model["features"]

        def done(t):
            try:
                row = [float(v) for v in t.replace(",", " ").split()]
                if not all(math.isfinite(v) for v in row):
                    raise ValueError
                r = predict(self.model, [row])[0]
            except (ValueError, MLError):
                return ("push", Message("Bad row", [f"Enter exactly {d} finite numbers, e.g. " + ", ".join("1" for _ in range(d))]))
            what = "cluster" if self.model["algo"] == "kmeans" else "prediction"
            return ("push", Message("Prediction", [f"{what}: {g(r)}"]))
        return ("push", Prompt("Predict", f"{d} feature values ({', '.join(self.names)})", "", done))

    def show_curve(self):
        if not self.model:
            return ("push", Message("No model", ["Train and evaluate first."]))
        return ("push", TextView("Loss curve", curve(self.loss)))

    def show_export(self):
        if not self.model:
            return ("push", Message("No model", ["Train and evaluate first."]))
        try:
            js = export(self.model)
        except ValueError:
            return ("push", Message("Cannot export", ["The model holds a non-finite number."]))
        ok = self.host.put("ml_model", js)
        return ("push", TextView("Model JSON", ["saved to the vault as ml_model" if ok else "could not save to the vault", ""] + wrap(js[:4000], 76)))


def make(host, entry):
    return Lab(host)


ENTRIES = [app("Machine Learning Lab", make, "partial",
               "Classical machine learning on small pasted CSV tables: linear and logistic regression, k-NN, k-means, "
               "decision tree, naive Bayes and a small neural network, with metrics and JSON export. It does NOT train or "
               "run language models or images, use a GPU, train distributed, fine-tune, or deploy models.")]

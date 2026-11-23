"""router.plan - reads a prompt and chooses WHERE it runs, HOW HARD the model works, and HOW MUCH of it runs.

Three choices, all made automatically and all overridable:
  where   local or cloud. Anything that looks like a secret stays local. Long or hard prompts go to cloud.
  effort  instant, low, medium, high or max, from a score of 0 to 100 worked out from the prompt.
  islands how many of the network's islands to run (router.islands publishes them). Effort sets the share
          of islands; the biggest run first; at least one always runs.
Optionally the prompt is tidied first (``o``): extra spaces, filler words and repeated lines go; you see both
versions and the tidied one is only used if you leave it on.

Honest limits. This is a hand-written rule score, not a trained model, so it will misjudge some prompts
(that is why every choice can be overridden). It does not send anything and does not run a model: the OS's own
password-gated ``ask`` does that, with one endpoint. Whole numbers only.
Keys: typing writes the prompt, Enter decides. Then o tidy, e effort, w where, n new prompt, Esc leaves."""

import json
import re

from kos.sdk import App

SPACE = "router"
ISLANDS_KEY = "islands"
TIERS = ("instant", "low", "medium", "high", "max")
SHARE = {"instant": 0, "low": 25, "medium": 50, "high": 75, "max": 100}    # percent of islands to run
CUTS = (12, 30, 50, 70)            # score below 12 is instant, below 30 low, below 50 medium, below 70 high
LOCAL_CHARS = 8000                 # a local model is assumed to hold about this much; longer goes to cloud
MAX_PROMPT = 20000
MAX_ISLANDS = 64
BAD = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")

HARD = ("prove", "derive", "step by step", "analyze", "analyse", "compare", "design", "optimize", "debug",
        "refactor", "algorithm", "architecture", "trade-off", "tradeoff", "explain why", "plan", "evaluate",
        "implement", "security", "complexity", "formal")
SECRET = ("password", "passphrase", "api key", "api_key", "apikey", "secret", "private key", "ssn",
          "social security", "credit card", "card number", "bearer ", "token:")
FILLER = re.compile(r"\b(?:please|kindly|um+|uh+|you know|i was wondering if you could)\b[,]?\s*", re.I)
CODE = ("```", "def ", "class ", "function ", "=>", "#include", "SELECT ", "{", ";")
MATH = ("integral", "equation", "derivative", "matrix", "probability", "theorem", "=", "^")


def clean(text):
    return BAD.sub("?", str(text))[:MAX_PROMPT]


def score(prompt):
    """0 to 100: how much thinking the prompt seems to need. Plain counting, no model."""
    p = prompt.strip()
    low = p.lower()
    words = len(p.split())
    if words == 0:
        return 0
    s = min(30, len(p) // 40)
    s += min(30, 6 * sum(1 for w in HARD if w in low))
    s += min(15, 5 * sum(1 for c in CODE if c in p))
    s += min(10, 3 * sum(1 for m in MATH if m in low))
    steps = p.count("?") + len(re.findall(r"(?m)^\s*(?:\d+[.)]|[-*])\s", p)) + low.count(" and then ")
    s += min(15, 3 * steps)
    return max(0, min(100, s))


def tier_of(sc):
    for name, cut in zip(TIERS, CUTS):
        if sc < cut:
            return name
    return TIERS[-1]


def looks_secret(prompt):
    low = prompt.lower()
    return [w for w in SECRET if w in low] or (["private key block"] if "-----begin" in low else [])


def tidy(prompt):
    """The prompt with filler words, extra spaces and repeated lines removed. Never returns an empty prompt."""
    out, seen = [], set()
    for raw in prompt.replace("\r", "").split("\n"):
        line = re.sub(r"[ \t]+", " ", FILLER.sub("", raw)).strip()
        if line and line.lower() not in seen:
            seen.add(line.lower())
            out.append(line)
        elif not line and out and out[-1]:
            out.append("")
    text = "\n".join(out).strip()
    return text if text else prompt.strip()


def island_count(n, tier):
    """How many of n islands run: the tier's share, rounded up, never fewer than 1, never more than n."""
    if n <= 0:
        return 0
    return min(n, max(1, (n * SHARE[tier] + 99) // 100))


def load_islands(raw):
    """Island sizes published by router.islands, or [] if missing or not what it should be."""
    try:
        d = json.loads(raw) if isinstance(raw, str) else None
    except ValueError:
        return []
    if not isinstance(d, list) or not 1 <= len(d) <= MAX_ISLANDS:
        return []
    out = []
    for i in d:
        if not isinstance(i, dict) or set(i) != {"id", "units", "edges", "inputs", "outputs"}:
            return []
        if not all(type(v) is int and 0 <= v <= 10 ** 9 for v in i.values()):
            return []
        out.append(i)
    return out


def decide(prompt, islands, tier_override=None, where_override=None, optimize=False):
    """The whole decision as plain data, so it can be shown and tested."""
    used = tidy(prompt) if optimize else prompt.strip()
    sc = score(used)
    auto = tier_of(sc)
    tier = tier_override or auto
    secrets = looks_secret(prompt)
    notes = []
    if where_override:
        where = where_override
        if where == "cloud" and secrets:
            notes.append("WARNING: this looks like it holds a secret (" + ", ".join(secrets[:3]) + "). "
                         "The OS will still ask your password before anything leaves.")
    elif secrets:
        where = "local"
        notes.append("kept on this computer: it mentions " + ", ".join(secrets[:3]))
        if tier in ("high", "max"):
            notes.append("a local model may struggle at this effort; you can force cloud with w")
    elif len(used) > LOCAL_CHARS:
        where = "cloud"
        notes.append(f"longer than {LOCAL_CHARS} characters, more than a local model is assumed to hold")
    elif tier in ("high", "max"):
        where = "cloud"
        notes.append("hard enough that a bigger model is worth sending it out for")
    else:
        where = "local"
    n = len(islands)
    k = island_count(n, tier)
    ran = sum(i["edges"] for i in islands[:k])
    whole = sum(i["edges"] for i in islands)
    share = ran * 100 // whole if whole else 100
    return {"prompt": used, "score": sc, "auto_tier": auto, "tier": tier, "where": where, "islands_total": n,
            "islands_run": k, "compute_percent": share, "notes": notes, "tidied": optimize and used != prompt.strip()}


def wrap(text, width):
    out = []
    for raw in str(text).split("\n"):
        line = raw
        while len(line) > width:
            cut = line.rfind(" ", 0, width)
            cut = cut if cut > 0 else width
            out.append(line[:cut])
            line = line[cut:].lstrip()
        out.append(line)
    return out


def lines(state, width, height):
    w = max(20, width - 4)
    out = [""]
    if state["phase"] == "input":
        out += ["  Type your prompt, Enter to decide:", ""]
        shown = (state["buf"] + "_").split("\n")
        for ln in shown[-max(3, height - 8):]:
            out += ["  " + x for x in wrap(ln, w)]
        return out
    d = state["d"]
    isl = f"{d['islands_run']} of {d['islands_total']}" if d["islands_total"] else "all (no island data: run router.islands and press p)"
    out += [f"  where   : {d['where'].upper()}{'  (forced)' if state['where'] else '  (auto)'}",
            f"  effort  : {d['tier']}{'  (forced)' if state['tier'] else '  (auto, score ' + str(d['score']) + ' of 100)'}",
            f"  islands : {isl}" + (f"   about {d['compute_percent']}% of the connections run" if d["islands_total"] else ""),
            f"  tidy    : {'ON ' if state['optimize'] else 'off'}"
            + ("  the prompt below is the tidied one" if d["tidied"] else "  (nothing to tidy)" if state["optimize"] else "")]
    for n in d["notes"]:
        out += wrap("  note: " + n, w + 2)
    out += ["", "  prompt used:"]
    shown = [x for ln in d["prompt"].split("\n") for x in wrap(ln, w)]
    room = max(3, height - len(out) - 3)
    out += ["    " + x for x in shown[:room]]
    if len(shown) > room:
        out.append("    ...")
    out += ["", "  Advice only. Nothing was sent. The OS's ask asks your password before anything leaves."]
    return out


def main():
    app = App()
    state = {"phase": "input", "buf": "", "optimize": False, "tier": None, "where": None, "d": None, "islands": []}
    for ev in app.events():
        cmd = ev["cmd"]
        if cmd == "hello":
            state["islands"] = load_islands(app.vault_get(ISLANDS_KEY, space=SPACE))
        elif cmd == "key":
            k = ev["key"]
            if k == "escape":
                if state["phase"] == "input" and state["buf"]:
                    state["buf"] = ""
                else:
                    app.exit(0)
                    return
            elif state["phase"] == "input":
                if k == "enter":
                    if state["buf"].strip():
                        state["phase"] = "result"
                elif k == "backspace":
                    state["buf"] = state["buf"][:-1]
                elif k == "space":
                    state["buf"] += " "
                elif len(k) == 1 and len(state["buf"]) < MAX_PROMPT:
                    state["buf"] += k
            else:
                if k == "o":
                    state["optimize"] = not state["optimize"]
                elif k == "e":
                    cycle = (None,) + TIERS
                    state["tier"] = cycle[(cycle.index(state["tier"]) + 1) % len(cycle)]
                elif k == "w":
                    cycle = (None, "local", "cloud")
                    state["where"] = cycle[(cycle.index(state["where"]) + 1) % len(cycle)]
                elif k == "n":
                    state.update(phase="input", buf="", tier=None, where=None)
        if state["phase"] == "result":
            state["d"] = decide(clean(state["buf"]), state["islands"], state["tier"], state["where"], state["optimize"])
        if cmd != "pointer":
            status = "Enter decide   Esc clears/leaves" if state["phase"] == "input" else "o tidy   e effort   w where   n new   Esc leaves"
            app.screen("Router", lines(state, app.width, app.height), status=status)

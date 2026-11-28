"""A small real search engine: tokenizer, BM25 ranking, snippets. Used by
notes, the knowledge base, enterprise/file search and the retrieval assistants."""

from __future__ import annotations

import math
import re
from collections import Counter

_WORD = re.compile(r"[\w'-]+", re.U)
STOP = set("a an and are as at be by for from has have in is it its of on or that the this to was were will with".split())


def tokens(text: str) -> list:
    return [w for w in (m.group(0).lower().strip("'-") for m in _WORD.finditer(text)) if w and w not in STOP]


class Index:
    def __init__(self, docs: dict[str, str] | None = None):
        self.docs: dict[str, str] = {}
        self.tf: dict[str, Counter] = {}
        self.df: Counter = Counter()
        self.len: dict[str, int] = {}
        for k, v in (docs or {}).items():
            self.add(k, v)

    def add(self, key: str, text: str) -> None:
        if key in self.docs:
            self.remove(key)
        t = tokens(text)
        self.docs[key], self.tf[key], self.len[key] = text, Counter(t), len(t)
        for w in self.tf[key]:
            self.df[w] += 1

    def remove(self, key: str) -> None:
        for w in self.tf.pop(key, {}):
            self.df[w] -= 1
            if self.df[w] <= 0:
                del self.df[w]
        self.docs.pop(key, None); self.len.pop(key, None)

    def search(self, query: str, limit: int = 20) -> list:
        """-> [(key, score, snippet)] best first. Prefix match on the last term."""
        q = tokens(query)
        if not q or not self.docs:
            return []
        n = len(self.docs)
        avg = (sum(self.len.values()) / n) or 1.0
        out = []
        for key, tf in self.tf.items():
            score = 0.0
            for i, term in enumerate(q):
                terms = [term]
                if i == len(q) - 1:
                    terms += [w for w in tf if w.startswith(term) and w != term]
                for t in terms:
                    f = tf.get(t, 0)
                    if not f:
                        continue
                    idf = math.log(1 + (n - self.df[t] + 0.5) / (self.df[t] + 0.5))
                    score += idf * f * 2.2 / (f + 1.2 * (0.25 + 0.75 * self.len[key] / avg))
            if score > 0:
                out.append((key, score, snippet(self.docs[key], q)))
        out.sort(key=lambda x: -x[1])
        return out[:limit]


def snippet(text: str, q: list, width: int = 70) -> str:
    low = text.lower()
    best = min((low.find(t) for t in q if low.find(t) >= 0), default=0)
    s = max(0, best - width // 3)
    return ("…" if s else "") + " ".join(text[s:s + width].split())

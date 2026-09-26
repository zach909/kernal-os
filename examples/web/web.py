"""`run web`: a browser with no graphics.

Type a URL and press Enter. The page is shown as a folder: every link on it
is an entry you can open (arrow keys + Enter, or click with the mouse).
Type `run` and Enter to view the current page's text. Backspace on an empty
line goes up (back). Esc exits.

It only gets network access if you allowed it with your password at launch.

Every page it fetches goes through the same static scanner everything else
in KOS goes through, before you ever see a byte of it: pages with a flagged
pattern are still shown (the scanner is heuristic, not a reason to hide
things from you), but the flag is right there in the status line.
"""

import urllib.parse
import urllib.request
from html.parser import HTMLParser

from kos.sdk import App
from kos.scan import scan_bytes

MAX_PAGE = 2 << 20


class Page(HTMLParser):
    def __init__(self, base):
        super().__init__()
        self.base, self.links, self.text, self.title = base, [], [], ""
        self._a = None
        self._skip = 0
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        elif tag == "title":
            self._in_title = True
        elif tag == "a":
            href = dict(attrs).get("href")
            if href and not href.startswith(("javascript:", "#", "mailto:")):
                self._a = [urllib.parse.urljoin(self.base, href), ""]

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        elif tag == "title":
            self._in_title = False
        elif tag == "a" and self._a:
            self.links.append((self._a[1].strip() or self._a[0], self._a[0]))
            self._a = None

    def handle_data(self, data):
        if self._skip:
            return
        if self._in_title:
            self.title += data
        if self._a:
            self._a[1] += data
        if data.strip():
            self.text.append(" ".join(data.split()))


def fetch(url):
    if "://" not in url:
        url = "https://" + url
    if not url.startswith(("http://", "https://")):
        raise ValueError("only http(s) URLs")
    req = urllib.request.Request(url, headers={"User-Agent": "kos-web/1.0"})
    with urllib.request.urlopen(req, timeout=15) as r:
        raw = r.read(MAX_PAGE)
        body = raw.decode(r.headers.get_content_charset() or "utf-8", "replace")
        page = Page(r.geturl())
    page.feed(body)
    page.scan = scan_bytes(raw, label=page.base)
    return page


def main():
    app = App()
    history, page, sel, typed, viewing, msg = [], None, 0, "", False, ""
    for ev in app.events():
        cmd = ev["cmd"]
        rows = max(5, app.height - 4)
        if cmd == "key":
            k = ev["key"]
            if k == "escape":
                app.exit(0)
                return
            if k == "enter":
                if typed.strip() == "run":
                    viewing, typed = True, ""
                elif typed.strip():
                    target, typed = typed.strip(), ""
                    try:
                        history.append(fetch(target)); sel, viewing, msg = 0, False, ""
                    except Exception as e:
                        msg = f"error: {e}"
                elif page and page.links and not viewing:
                    try:
                        history.append(fetch(page.links[sel][1])); sel, msg = 0, ""
                    except Exception as e:
                        msg = f"error: {e}"
            elif k == "backspace":
                if typed:
                    typed = typed[:-1]
                elif viewing:
                    viewing = False
                elif len(history) > 1:
                    history.pop(); sel = 0
            elif k == "up":
                sel = max(0, sel - 1)
            elif k == "down" and page:
                sel = min(len(page.links) - 1, sel + 1)
            elif len(k) == 1:
                typed += k
        elif cmd == "button" and ev["pressed"] and page and not viewing:
            top = max(0, sel - rows + 1)
            i = top + ev["y"] - 2
            if 0 <= i < len(page.links):
                sel = i
        page = history[-1] if history else None
        if page is None:
            lines = ["", "  Type a URL (e.g. example.com) and press Enter."]
        elif viewing:
            lines = [f"  {page.base}", ""] + ["  " + t for t in page.text][:rows]
        else:
            top = max(0, sel - rows + 1)
            lines = [f"  {page.base}/", ""]
            for i, (label, _) in enumerate(page.links[top:top + rows], top):
                lines.append(("> " if i == sel else "  ") + f"[{label[:70]}]/")
            if not page.links:
                lines.append("  (empty folder: no links; type 'run' to view the page)")
        lines += ["", f"  > {typed}_", f"  {msg}"]
        title = (page.title.strip() if page else "") or "web"
        scan_note = ""
        if page is not None and getattr(page, "scan", None) is not None:
            scan_note = " | SCAN: clean" if page.scan.clean else \
                f" | SCAN: FLAGGED ({page.scan.summary()})"
        app.screen(title, lines,
                  status=f"URL+Enter: go | Enter: open | run: view | Bksp: back | Esc{scan_note}")

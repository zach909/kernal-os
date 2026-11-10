"""`run web`: a browser with no graphics.

Type a URL and press Enter. The page is shown as a folder: every link on it
is an entry you can open (arrow keys + Enter, or click with the mouse).
Type `run` and Enter to view the current page's text. Backspace on an empty
line goes up (back). Esc exits.

It has NO network of its own. Every page is fetched by the OS for it (request fetch), and only if the
owner's firewall has a rule `app:web HOST PORT https` (kos firewall allow app:web example.com 443 --proto https);
otherwise the page is "blocked". Redirects are refused (no silent hop, never encrypted to plain).

Addresses: `kos go kos://web/example.com/news?page=2` opens this browser straight at
example.com/news?page=2 - an app opened the way a browser opens a website.

Extensions: an extension the owner switched on for this app (`kos extend NAME`) can add bookmarks,
shown on the start page. They are data: entries whose address is `kos://web/SITE`.

Every page it fetches goes through the same static scanner everything else
in KOS goes through, before you ever see a byte of it: pages with a flagged
pattern are still shown (the scanner is heuristic, not a reason to hide
things from you), but the flag is right there in the status line.
"""

import re
import urllib.parse
from html.parser import HTMLParser

from kos.address import AddressError, parse as parse_address
from kos.sdk import App
from kos.scan import scan_bytes

MAX_PAGE = 2 << 20

# Shown on every screen, including the empty start screen. A website you open
# learns where the request came from; the browser says so instead of hiding it.
IP_NOTICE = "Websites you visit can see your IP address."


def start_target(address):
    """The site a kos://web/SITE address asks for (``/example.com/news?p=2`` -> ``example.com/news?p=2``)."""
    return address[1:] if address.startswith("/") and len(address) > 1 else ""


def bookmarks(extensions):
    """[(label, site)] from the switched-on extensions' entries that point at this browser."""
    out = []
    for item in extensions:
        for e in item.get("entries", []):
            try:
                a = parse_address(e["address"])
            except (AddressError, KeyError):
                continue
            if a.app == "web" and start_target(a.launch):
                out.append((e["label"], start_target(a.launch)))
    return out[:12]


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


def check_url(url):
    """The URL to fetch, or ValueError. Every connection must be encrypted:
    plain http:// is refused, not upgraded behind your back, and a bare
    'example.com' means https://example.com."""
    url = url.strip()
    if "://" not in url:
        # 'javascript:x', 'mailto:x', 'data:x' are schemes, not host names;
        # 'host:443/path' (a colon then digits) is a host and port.
        if re.match(r"[A-Za-z][A-Za-z0-9+.-]*:(?!\d+(/|$))", url):
            raise ValueError("only https:// URLs")
        url = "https://" + url
    parts = urllib.parse.urlsplit(url)
    try:
        parts.port
    except ValueError:
        raise ValueError("invalid port") from None
    if parts.scheme == "http":
        raise ValueError("refused: http:// is not encrypted (https:// only)")
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError("only https:// URLs")
    return url


_WHY = {"blocked": "blocked by the firewall: the owner allows a site with `kos firewall allow app:web HOST 443 --proto https`",
        "refused": "refused: could not verify this site's certificate (or this app has no network permission)",
        "unreachable": "could not reach the site", "redirect": "refused: the site redirected (redirects are never followed)",
        "too-big": "refused: the page is too big", "bad-url": "refused: not a plain https:// address"}


def fetch(app, url):
    """Ask the OS for one page. Certificates and host names are verified by the OS; the app cannot
    turn that off, and there are no redirects. check_url stays as defence in depth."""
    url = check_url(url)
    ok, got = app.fetch(url, "GET", {"user-agent": "kos-web/1.0"})
    if not ok:
        raise ValueError(_WHY.get(got, "could not fetch this page"))
    raw = got["body"][:MAX_PAGE]
    m = re.search(r"charset=([A-Za-z0-9_-]{1,30})", got["content_type"])
    try:
        body = raw.decode(m.group(1) if m else "utf-8", "replace")
    except LookupError:
        body = raw.decode("utf-8", "replace")
    page = Page(url)
    page.feed(body)
    page.scan = scan_bytes(raw, label=page.base)
    return page


def build_lines(page, viewing, sel, rows, typed, msg):
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
    return lines + ["", f"  ! {IP_NOTICE}", f"  > {typed}_", f"  {msg}"]


def main():
    app = App()
    history, page, sel, typed, viewing, msg = [], None, 0, "", False, ""
    for ev in app.events():
        cmd = ev["cmd"]
        rows = max(5, app.height - 4)
        marks = bookmarks(app.extensions)
        if cmd == "hello" and start_target(app.address):
            try:
                history.append(fetch(app, start_target(app.address)))
            except Exception as e:
                msg = f"error: {e}"
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
                        history.append(fetch(app, target)); sel, viewing, msg = 0, False, ""
                    except Exception as e:
                        msg = f"error: {e}"
                elif page is None and marks:
                    try:
                        history.append(fetch(app, marks[min(sel, len(marks) - 1)][1])); sel, msg = 0, ""
                    except Exception as e:
                        msg = f"error: {e}"
                elif page and page.links and not viewing:
                    try:
                        history.append(fetch(app, page.links[sel][1])); sel, msg = 0, ""
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
            elif k == "down" and (page or marks):
                sel = min((len(page.links) if page else len(marks)) - 1, sel + 1)
            elif len(k) == 1:
                typed += k
        elif cmd == "button" and ev["pressed"] and page and not viewing:
            top = max(0, sel - rows + 1)
            i = top + ev["y"] - 2
            if 0 <= i < len(page.links):
                sel = i
        page = history[-1] if history else None
        lines = build_lines(page, viewing, sel, rows, typed, msg)
        if page is None:
            lines = ["", "  Type a URL (e.g. example.com) and press Enter."]
            if marks:
                lines += ["", "  Bookmarks (from your extensions) - up/down, Enter:"]
                for i, (label, site) in enumerate(marks):
                    lines.append(("  > " if i == sel else "    ") + f"{label[:24]:<24} {site[:40]}")
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

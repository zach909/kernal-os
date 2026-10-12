'use strict';
// Search. Type anywhere on the desktop and this app finds apps AND the commands they offer.
// Anything else you type is a command too - print(1), or a plain-language line - and the
// first result runs it in the terminal. It asks the OS for more room when it has results.
const path = require('path');
const { App, Canvas } = require(process.env.KOS_SDK_JS);
const dir = path.dirname(process.env.KOS_SDK_JS);
const G = require(path.join(dir, 'gfx.js'));
const K = require(path.join(dir, 'kit.js'));

const SHELL = K.SHELL;
const ACCENT = G.ACCENT;
const CODE = /[()=\[\]{};]|^(print|import|def|class|for|while|let|const|var|echo|if)\b/i;

(async () => {
  const app = new App();
  const st = { apps: [], query: '', sel: 0, active: false, note: '', asked: 0 };
  const items = () => {
    const out = [];
    for (const a of st.apps.filter((x) => !SHELL.has(x.name) && !x.slot)) {
      out.push({ kind: 'app', name: a.name, app: a.name, sub: a.description, words: [a.description, ...a.commands.flatMap((c) => [c.title, ...c.keywords])], boost: 3 });
      for (const c of a.commands) out.push({ kind: 'command', name: c.title, app: a.name, id: c.id, sub: `in ${a.name}`, words: [c.id, ...c.keywords, a.name] });
    }
    return out;
  };
  const results = () => {
    const q = st.query.trim();
    if (!q) return [];
    const run = { kind: 'line', name: `RUN: ${q}`, app: 'terminal', line: q, sub: CODE.test(q) ? 'run it as a command (code runs in a sandbox)' : 'run it as a command in the terminal' };
    const found = K.rank(items(), q, 8);
    return CODE.test(q) || !found.length ? [run, ...found] : [...found, run];
  };
  const run = (r) => {
    st.note = '';
    if (r.kind === 'line') app.requestOpen('terminal', 'graphical', 'line', r.line);
    else app.requestOpen(r.app, 'graphical', r.kind === 'command' ? r.id : '');
    st.query = ''; st.sel = 0;
  };
  const rowH = () => 24 * app.scale;
  const draw = () => {
    const c = new Canvas(), u = app.scale, W = app.width, res = results();
    const want = st.query ? 26 * u + 8 * u + Math.max(1, res.length) * rowH() + 8 * u : 26 * u + 2;
    if (Math.abs(want - app.height) > 2 && st.asked !== want) { st.asked = want; app.requestResize(0, want); }
    const px = 8 * u, ty = Math.round((26 * u - px * 1.2) / 2) + 1;
    G.roundRect(c, 0, 0, W, 26 * u + 2, 13 * u, st.active || st.query ? ACCENT : '#aab4c4');
    G.roundRect(c, 1, 1, W - 2, 26 * u, 13 * u - 1, '#14171c');
    c.hit(0, 0, W, 26 * u + 2, 'Search');
    G.ring(c, 14 * u, 12 * u, 4 * u, '#cfe3ff'); c.line(17 * u, 15 * u, 21 * u, 19 * u, '#cfe3ff');           // magnifier
    const room = W - 44 * u;
    let q = st.query;
    while (q && app.textWidth(q + '_', px) > room) q = q.slice(1);
    if (q) c.stext(30 * u, ty, q + (Math.floor(Date.now() / 500) % 2 ? '|' : ''), '#ffffff', px);
    else c.stext(30 * u, ty, 'Search apps and commands, or run anything: print(1)', '#9aa3b2', px);
    if (q) {
      const py = 32 * u;
      G.roundRect(c, 0, py, W, Math.max(1, res.length) * rowH() + 8 * u, 10 * u, '#171a21');
      res.forEach((r, i) => {
        const y = py + 4 * u + i * rowH();
        if (i === st.sel) G.roundRect(c, 4 * u, y, W - 8 * u, rowH() - 2 * u, 7 * u, ACCENT);
        c.hit(4 * u, y, W - 8 * u, rowH() - 2 * u, r.name);
        G.icon(c, 10 * u, y + 2 * u, 18 * u, r.app);
        const name = r.name, sub = (r.kind === 'app' ? 'App' : r.kind === 'command' ? 'Command' : 'Run') + ' - ' + String(r.sub || '');
        c.stext(36 * u, y + 2 * u, name, '#ffffff', 7 * u + 1, 1);
        c.stext(36 * u, y + 2 * u + 9 * u, sub.slice(0, Math.floor((W - 44 * u) / (3.4 * u))), i === st.sel ? '#dbeeff' : r.kind === 'line' ? '#7ee0a8' : '#9fb2c8', 5 * u + 2);
      });
    }
    if (st.note) c.stext(8 * u, 26 * u + 6, st.note.slice(0, 80), '#ffd27a', 7 * u);
    app.present(c);
  };
  const rowAt = (y) => { const i = Math.floor((y - 32 * app.scale - 4 * app.scale) / rowH()); return i >= 0 && i < results().length ? i : -1; };
  for await (const ev of app.events()) {
    if (ev.cmd === 'hello') { app.requestApps(); st.asked = 0; }
    else if (ev.cmd === 'apps') st.apps = ev.installed;
    else if (ev.cmd === 'focus') { st.active = true; st.query = ''; st.sel = 0; }
    else if (ev.cmd === 'result' && !ev.ok && ev.action === 'open') st.note = ev.detail;
    else if (ev.cmd === 'key') {
      const k = ev.key, res = results(); st.active = true;
      if (k === 'escape') { st.query = ''; st.sel = 0; }
      else if (k === 'backspace') { st.query = st.query.slice(0, -1); st.sel = 0; }
      else if (k === 'enter') { if (res[st.sel]) run(res[st.sel]); }
      else if (k === 'down' && res.length) st.sel = (st.sel + 1) % res.length;
      else if (k === 'up' && res.length) st.sel = (st.sel - 1 + res.length) % res.length;
      else if (k.length === 1 && k >= ' ') { st.query += k; st.sel = 0; }
    } else if (ev.cmd === 'button' && ev.pressed && ev.button === 'left') { const i = rowAt(ev.y); if (i >= 0) run(results()[i]); }
    else continue;
    draw();
  }
})();

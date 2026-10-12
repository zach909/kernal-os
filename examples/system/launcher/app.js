'use strict';
// The launcher: press the Super key (or click KOS in the top panel) and every app is here. Type to search apps
// AND the commands they offer (the same search as the desktop's search box); any other line runs as a command.
// Arrows move, Enter opens, Esc closes. Opening anything is a request: the OS asks for your password.
const path = require('path');
const { App, Canvas } = require(process.env.KOS_SDK_JS);
const dir = path.dirname(process.env.KOS_SDK_JS);
const G = require(path.join(dir, 'gfx.js'));
const K = require(path.join(dir, 'kit.js'));
const CODE = /[()=\[\]{};]|^(print|import|def|class|for|while|let|const|var|echo|if)\b/i;

(async () => {
  const app = new App();
  const st = { apps: [], query: '', sel: 0, zones: [], hover: -1, shown: true };
  const launchable = () => st.apps.filter((a) => !K.SHELL.has(a.name) && !a.slot);
  const items = () => {
    const out = [];
    for (const a of launchable()) {
      out.push({ kind: 'app', name: a.name, app: a.name, sub: a.description, words: [a.description, ...a.commands.flatMap((c) => [c.title, ...c.keywords])], boost: 3 });
      for (const c of a.commands) out.push({ kind: 'command', name: c.title, app: a.name, id: c.id, sub: `in ${a.name}`, words: [c.id, ...c.keywords, a.name] });
    }
    return out;
  };
  const entries = () => {
    const q = st.query.trim();
    if (!q) return launchable().map((a) => ({ kind: 'app', name: a.name, app: a.name, sub: a.description }));
    const found = K.rank(items(), q, 24), run = { kind: 'line', name: `Run: ${q}`, app: 'terminal', line: q, sub: 'run it as a command in the terminal' };
    return CODE.test(q) || !found.length ? [run, ...found] : [...found, run];
  };
  const label = (n) => n.replace(/-/g, ' ').replace(/^./, (m) => m.toUpperCase());
  const run = (r) => {
    if (!r) return;
    if (r.kind === 'line') app.requestOpen('terminal', 'graphical', 'line', r.line);
    else app.requestOpen(r.app, 'graphical', r.kind === 'command' ? r.id : '');
    st.query = ''; st.sel = 0;
    app.requestToggle('launcher');                       // close ourselves; the OS asks for the password in its own prompt
  };
  const draw = () => {
    const c = new Canvas(), u = app.scale, W = app.width, H = app.height, px = 7 * u, list = entries();
    st.zones = [];
    const bx = 12 * u, bw = W - 24 * u;
    c.hit(bx, 10 * u, bw, 22 * u, 'Search');
    G.roundRect(c, bx, 10 * u, bw, 22 * u, 11 * u, st.query ? G.ACCENT : '#aab4c4'); G.roundRect(c, bx + 1, 11 * u, bw - 2, 22 * u - 2, 11 * u - 1, '#14171c');
    G.ring(c, bx + 12 * u, 21 * u, 4 * u, '#cfe3ff'); c.line(bx + 15 * u, 24 * u, bx + 19 * u, 28 * u, '#cfe3ff');
    G.stext(c, app, bx + 26 * u, 14 * u, st.query ? st.query + (Math.floor(Date.now() / 500) % 2 ? '|' : '') : 'Search apps and commands, or run anything', st.query ? '#ffffff' : '#8a93a6', px, 0, null);
    if (!st.query) {
      const cols = Math.max(2, Math.floor((W - 16 * u) / (84 * u))), cw = Math.floor((W - 16 * u) / cols), ch = 66 * u;
      list.forEach((a, i) => {
        const col = i % cols, row = Math.floor(i / cols), x = 8 * u + col * cw, y = 42 * u + row * ch, isz = 36 * u, on = i === st.sel || i === st.hover;
        if (y + ch > H) return;
        c.hit(x, y, cw, ch, label(a.name));
        if (on) G.roundRect(c, x + 3 * u, y - 2 * u, cw - 6 * u, ch - 2 * u, 8 * u, i === st.sel ? G.ACCENT : '#2f3541');
        G.icon(c, x + Math.round((cw - isz) / 2), y + 2 * u, isz, a.name, { hot: on });
        G.stextCentered(c, app, x + cw / 2, y + isz + 7 * u, label(a.name).slice(0, 13), '#ffffff', 6 * u, 0, '#000000');
        st.zones.push({ x, y, w: cw, h: ch, i });
      });
    } else {
      const rh = 22 * u;
      list.slice(0, Math.floor((H - 42 * u) / rh)).forEach((r, i) => {
        const y = 40 * u + i * rh;
        c.hit(8 * u, y, W - 16 * u, rh - 2 * u, r.name);
        if (i === st.sel) G.roundRect(c, 8 * u, y, W - 16 * u, rh - 2 * u, 7 * u, G.ACCENT);
        G.icon(c, 14 * u, y + 2 * u, 16 * u, r.app);
        G.stext(c, app, 38 * u, y + 2 * u, r.name, '#ffffff', 7 * u, 1, null);
        G.stext(c, app, 38 * u, y + 11 * u, `${r.kind === 'app' ? 'App' : r.kind === 'command' ? 'Command' : 'Run'} - ${String(r.sub || '').slice(0, 60)}`, i === st.sel ? '#dbeeff' : '#9fb2c8', 5 * u + 1, 0, null);
        st.zones.push({ x: 8 * u, y, w: W - 16 * u, h: rh, i });
      });
    }
    app.present(c);
  };
  const zoneAt = (x, y) => st.zones.find((z) => x >= z.x && x < z.x + z.w && y >= z.y && y < z.y + z.h);
  for await (const ev of app.events()) {
    if (ev.cmd === 'hello') app.requestApps();
    else if (ev.cmd === 'apps') st.apps = ev.installed;
    else if (ev.cmd === 'focus') { st.query = ''; st.sel = 0; app.requestApps(); }
    else if (ev.cmd === 'launch') { if (ev.command === 'show') app.requestToggle('launcher'); continue; }
    else if (ev.cmd === 'pointer') { const z = zoneAt(ev.x, ev.y), h = z ? z.i : -1; if (h === st.hover) continue; st.hover = h; }
    else if (ev.cmd === 'button' && ev.pressed && ev.button === 'left') { const z = zoneAt(ev.x, ev.y); if (z) run(entries()[z.i]); continue; }
    else if (ev.cmd === 'key') {
      const k = ev.key, list = entries();
      if (k === 'escape') { if (st.query) { st.query = ''; st.sel = 0; } else { app.requestToggle('launcher'); continue; } }
      else if (k === 'enter') { run(list[st.sel]); continue; }
      else if (k === 'backspace') { st.query = st.query.slice(0, -1); st.sel = 0; }
      else if (k === 'down' || k === 'right') st.sel = list.length ? (st.sel + 1) % list.length : 0;
      else if (k === 'up' || k === 'left') st.sel = list.length ? (st.sel - 1 + list.length) % list.length : 0;
      else if (k.length === 1 && k >= ' ') { st.query += k; st.sel = 0; }
    } else continue;
    draw();
  }
})();

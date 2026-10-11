'use strict';
// The dock: pinned apps, then anything else that is running, centered at the bottom on glass.
// A dot under an icon means the app is open (Windows Blue when it is the active one). Click to
// open it, or to bring its window forward. The dock asks the OS to size it to its icons; the OS
// keeps it centered.
const path = require('path');
const { App, Canvas } = require(process.env.KOS_SDK_JS);
const dir = path.dirname(process.env.KOS_SDK_JS);
const G = require(path.join(dir, 'gfx.js'));
const K = require(path.join(dir, 'kit.js'));
const ACCENT = '#0078d4';
const PINNED = ['files', 'terminal', 'editor', 'app-library', 'settings', 'security'];

(async () => {
  const app = new App();
  const st = { apps: [], windows: [], hover: -1, asked: 0, slots: [] };
  const items = () => {
    const have = new Set(st.apps.map((a) => a.name)), out = PINNED.filter((n) => have.has(n)).map((n) => ({ name: n, pinned: true }));
    for (const w of st.windows) if (!out.some((o) => o.name === w.name) && !K.SHELL.has(w.name)) out.push({ name: w.name, pinned: false });
    return out;
  };
  const geometry = () => {
    const u = app.scale, n = items().length, icon = 20 * u, gap = 6 * u, pad = 10 * u;
    return { u, icon, gap, pad, width: pad * 2 + n * icon + Math.max(0, n - 1) * gap };
  };
  const draw = () => {
    const c = new Canvas(), g = geometry(), H = app.height, list = items();
    if (Math.abs(g.width - app.width) > 1 && st.asked !== g.width) { st.asked = g.width; app.requestResize(g.width, 0); }
    st.slots = [];
    const sep = list.findIndex((o) => !o.pinned);
    list.forEach((it, i) => {
      const x = g.pad + i * (g.icon + g.gap), hot = i === st.hover, wins = st.windows.filter((w) => w.name === it.name);
      const lift = hot ? 3 * g.u : 0, y = Math.round((H - g.icon) / 2) - 2 * g.u - lift;
      G.icon(c, x, y, g.icon, it.name, { hot });
      if (wins.length) {
        const active = wins.some((w) => w.focused);
        G.circle(c, x + Math.round(g.icon / 2), H - 4 * g.u, Math.round(1.6 * g.u) + (active ? 1 : 0), active ? ACCENT : '#ffffff');
      }
      st.slots.push({ x: x - g.gap / 2, w: g.icon + g.gap, name: it.name, wins });
    });
    if (sep > 0) c.rect(g.pad + sep * (g.icon + g.gap) - Math.round(g.gap / 2) - 1, Math.round(H * 0.22), 1, Math.round(H * 0.5), '#ffffff');
    app.present(c);
  };
  const at = (x) => st.slots.findIndex((s) => x >= s.x && x < s.x + s.w);
  for await (const ev of app.events()) {
    if (ev.cmd === 'hello') { app.requestApps(); st.asked = 0; }
    else if (ev.cmd === 'apps') st.apps = ev.installed;
    else if (ev.cmd === 'windows') st.windows = ev.windows;
    else if (ev.cmd === 'pointer') { const h = at(ev.x); if (h === st.hover) continue; st.hover = h; }
    else if (ev.cmd === 'button' && ev.pressed && ev.button === 'left') {
      const s = st.slots[at(ev.x)];
      if (s) { const w = s.wins[s.wins.length - 1]; if (w) app.requestFocus(w.id); else app.requestOpen(s.name, 'graphical'); }
      continue;
    } else continue;
    draw();
  }
})();

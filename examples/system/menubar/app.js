'use strict';
// The top panel. Left: the KOS menu, the active app's name, and the commands that app offers
// (they are its menus: click one to run it). Right: CPU and memory, network, date and clock.
// It only draws and asks; opening anything is a request the OS answers.
const path = require('path');
const { App, Canvas } = require(process.env.KOS_SDK_JS);
const G = require(path.join(path.dirname(process.env.KOS_SDK_JS), 'gfx.js'));
const ACCENT = '#0078d4';
const DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const two = (n) => String(n).padStart(2, '0');

(async () => {
  const app = new App();
  const st = { sudo: { active: false, left: 0 }, windows: [], desktop: '', apps: [], local: null, online: null, cpu: 0, mem: 0, prev: null, n: 0, hover: -1, items: [] };
  const focused = () => st.windows.find((w) => w.focused);
  const draw = () => {
    const c = new Canvas(), u = app.scale, W = app.width, H = app.height, px = 7 * u + 1, ty = Math.round((H - px * 1.2) / 2);
    const tw = (s, face = 0, p = px) => app.textWidth(s, p, face);
    st.items = [];
    let x = 10 * u;
    const label = (s, face, action, color = '#ffffff') => {
      const w = tw(s, face), i = st.items.length, hot = action && st.hover === i;
      if (hot) G.roundRect(c, x - 5 * u, 2 * u, w + 10 * u, H - 4 * u, 3 * u, ACCENT);
      c.stext(x + 1, ty + 1, s, '#000000', px, face);
      c.stext(x, ty, s, color, px, face);
      if (action) c.hit(x - 5 * u, 2 * u, w + 10 * u, H - 4 * u, s);
      st.items.push({ x: x - 5 * u, w: w + 10 * u, action });
      x += w + 16 * u;
    };
    label('KOS', 1, () => app.requestToggle('launcher'));     // the KOS menu opens the launcher
    const f = focused(), meta = f && st.apps.find((a) => a.name === f.name);
    label(f ? f.name.replace(/(^|-)(\w)/g, (m, a, b) => (a ? ' ' : '') + b.toUpperCase()) : 'Desktop', 1, null);
    if (meta) for (const cmd of meta.commands.slice(0, 4)) label(cmd.title, 0, () => app.requestOpen(meta.name, 'graphical', cmd.id), '#dfe8f5');
    // right side, from the edge inward
    let r = W - 10 * u;
    const l = st.local, clock = l ? `${DAYS[l.weekday]} ${l.day} ${MONTHS[l.month - 1]}   ${two(l.hour)}:${two(l.minute)}` : '';
    r -= tw(clock, 1); c.stext(r + 1, ty + 1, clock, '#000000', px, 1); c.stext(r, ty, clock, '#ffffff', px, 1);
    if (st.sudo.active) {                                     // a sudo window is open: the password is being remembered
      const t = `sudo ${Math.floor(st.sudo.left / 60)}:${String(st.sudo.left % 60).padStart(2, '0')}`, w = tw(t, 1, px - 1) + 14 * u;
      r -= w + 6 * u;
      G.roundRect(c, r, 3 * u, w, H - 6 * u, Math.round((H - 6 * u) / 2), ACCENT);
      c.stext(r + 7 * u, ty + 1, t, '#ffffff', px - 1, 1);
    }
    r -= 26 * u;
    for (let i = 0; i < 4; i++) {
      const bh = (i + 1) * 2 * u + 2 * u;
      c.rect(r + i * 4 * u, Math.round((H + 8 * u) / 2) - bh, 3 * u, bh, st.online === null ? '#8a93a6' : st.online ? '#ffffff' : '#ff6b6b');
    }
    r -= 16 * u;
    const stats = `CPU ${Math.round(st.cpu * 100)}%   Memory ${Math.round(st.mem * 100)}%`;
    r -= tw(stats, 0, px - 1); c.stext(r, ty + 1, stats, '#c9d6ea', px - 1, 0);
    app.present(c);
  };
  const at = (x) => st.items.findIndex((it) => it.action && x >= it.x && x < it.x + it.w);
  for await (const ev of app.events()) {
    if (ev.cmd === 'hello') { app.requestSudo('status'); app.requestApps(); app.requestSys('resources'); app.requestSys('network'); }
    else if (ev.cmd === 'apps') st.apps = ev.installed;
    else if (ev.cmd === 'sudo') st.sudo = ev;
    else if (ev.cmd === 'windows') { st.windows = ev.windows; st.desktop = ev.desktop; }
    else if (ev.cmd === 'tick') {
      st.local = ev.local; st.n++;
      if (st.sudo.active || st.n % 5 === 0) app.requestSudo('status');
      if (st.n % 2 === 0) app.requestSys('resources');
      if (st.n % 15 === 1) app.requestSys('network');
    } else if (ev.cmd === 'sys' && ev.kind === 'resources') {
      const d = ev.data, total = d.cpu_ticks.reduce((a, b) => a + b, 0), idle = (d.cpu_ticks[3] || 0) + (d.cpu_ticks[4] || 0);
      if (st.prev && total > st.prev.total) st.cpu = 1 - (idle - st.prev.idle) / (total - st.prev.total);
      st.prev = { total, idle }; st.mem = 1 - d.mem_kb.MemAvailable / d.mem_kb.MemTotal;
    } else if (ev.cmd === 'sys' && ev.kind === 'network') st.online = ev.data.interfaces.some((i) => i.name !== 'lo' && i.state === 'up' && i.ipv4);
    else if (ev.cmd === 'pointer') { const h = at(ev.x); if (h === st.hover) continue; st.hover = h; }
    else if (ev.cmd === 'button' && ev.pressed && ev.button === 'left') { const h = at(ev.x); if (h >= 0) st.items[h].action(); continue; }
    else continue;
    draw();
  }
})();

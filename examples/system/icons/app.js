'use strict';
// The app icons. Every installed app as a glossy icon drawn by code; click one to open it.
// It draws no background (the wallpaper is another app, underneath), and it never starts
// anything itself: opening is a request, which the OS answers by opening a window.
const path = require('path');
const { App, Canvas } = require(process.env.KOS_SDK_JS);
const G = require(path.join(path.dirname(process.env.KOS_SDK_JS), 'gfx.js'));
const K = require(path.join(path.dirname(process.env.KOS_SDK_JS), 'kit.js'));

const SHELL = K.SHELL;

(async () => {
  const app = new App();
  const st = { apps: [], windows: [], hover: -1 };
  const launchable = () => st.apps.filter((a) => !SHELL.has(a.name));
  const geometry = () => {
    const u = app.scale, n = launchable().length;
    let cell = { w: 76 * u, h: 72 * u }, cols = Math.max(1, Math.floor(app.width / cell.w)), k = 1;
    const rows = Math.max(1, Math.ceil(n / cols));
    if (rows * cell.h > app.height) { k = Math.max(0.55, app.height / (rows * cell.h)); cell = { w: Math.round(cell.w * k), h: Math.round(cell.h * k) }; cols = Math.max(1, Math.floor(app.width / cell.w)); }
    return { u, cell, cols, k };
  };
  const tileAt = (x, y) => {
    const g = geometry(), col = Math.floor(x / g.cell.w), row = Math.floor(y / g.cell.h), i = row * g.cols + col;
    return x >= 0 && y >= 0 && col < g.cols && i < launchable().length ? i : -1;
  };
  const draw = () => {
    const c = new Canvas(), g = geometry(), u = g.u;
    launchable().forEach((a, i) => {
      const col = i % g.cols, row = Math.floor(i / g.cols), isz = Math.round(44 * u * g.k);
      const x = col * g.cell.w + (g.cell.w - isz) / 2, y = row * g.cell.h, hot = i === st.hover;
      G.icon(c, Math.round(x), Math.round(y - (hot ? 2 * u : 0)), isz, a.name, { hot });
      const label = a.name.replace(/-/g, ' ').replace(/^./, (m) => m.toUpperCase()), px = Math.round(6.5 * u * g.k) + 1;
      const lx = Math.round(col * g.cell.w + g.cell.w / 2 - app.textWidth(label, px) / 2), ly = Math.round(y + isz + 5 * u);
      c.stext(lx + 1, ly + 1, label, '#00305a', px); c.stext(lx, ly, label, '#ffffff', px);
      if (st.windows.some((w) => w.name === a.name)) c.rect(Math.round(x + isz / 2 - 4 * u), Math.round(y + isz + 17 * u), 8 * u, 2 * u, G.ACCENT);
    });
    app.present(c);
  };
  for await (const ev of app.events()) {
    if (ev.cmd === 'hello') app.requestApps();
    else if (ev.cmd === 'apps') st.apps = ev.installed;
    else if (ev.cmd === 'windows') st.windows = ev.windows;
    else if (ev.cmd === 'pointer') { const h = tileAt(ev.x, ev.y); if (h === st.hover) continue; st.hover = h; }
    else if (ev.cmd === 'button' && ev.pressed && ev.button === 'left') { const i = tileAt(ev.x, ev.y); if (i >= 0) app.requestOpen(launchable()[i].name, 'graphical'); continue; }
    else continue;
    draw();
  }
})();

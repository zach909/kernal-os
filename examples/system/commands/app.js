'use strict';
// Commands: what one app can do. In the 3D look every app has a waterfall of its own words running down to the lake; clicking
// it opens this window for that app. Each row is a command the app offers; clicking one opens the app and runs it (the OS asks for
// your password, as it always does). The first row just opens the app.
const path = require('path');
const { App, Canvas } = require(process.env.KOS_SDK_JS);
const G = require(path.join(path.dirname(process.env.KOS_SDK_JS), 'gfx.js'));

(async () => {
  const app = new App();
  const st = { target: '', apps: [], hover: -1, zones: [] };
  const info = () => st.apps.find((a) => a.name === st.target);
  const rows = () => {
    const a = info();
    if (!a) return [];
    const mode = a.modes.includes('graphical') ? 'graphical' : a.modes[0] || 'tui';
    return [{ title: `Open ${st.target}`, sub: a.description || '', id: '', mode },
      ...a.commands.map((c) => ({ title: c.title, sub: c.id, id: c.id, mode }))];
  };
  const draw = () => {
    G.setLook(app.look);
    const c = new Canvas(), u = app.scale, W = app.width, H = app.height, list = rows();
    st.zones = [];
    G.stext(c, app, 14 * u, 10 * u, st.target ? `${st.target}: commands` : 'Commands', '#ffffff', 11 * u, 1);
    if (!info()) G.stext(c, app, 14 * u, 30 * u, st.target ? `${st.target} is not installed` : 'Click an app\'s waterfall in the 3D look.', '#9fb2c8', 7 * u, 0);
    list.forEach((r, i) => {
      const y = 34 * u + i * 24 * u, on = i === st.hover;
      if (y + 22 * u > H) return;
      c.hit(10 * u, y, W - 20 * u, 22 * u, r.title);
      G.roundRect(c, 10 * u, y, W - 20 * u, 22 * u, 7 * u, on ? G.ACCENT : '#262b34');
      G.stext(c, app, 20 * u, y + 3 * u, r.title, '#ffffff', 8 * u, 1, null);
      G.stext(c, app, 20 * u, y + 13 * u, String(r.sub).slice(0, 70), on ? '#dbeeff' : '#8a93a6', 6 * u, 0, null);
      st.zones.push({ y, h: 22 * u, i });
    });
    app.present(c);
  };
  const zoneAt = (y) => st.zones.find((z) => y >= z.y && y < z.y + z.h);
  for await (const ev of app.events()) {
    if (ev.cmd === 'hello') app.requestApps();
    else if (ev.cmd === 'launch') { if (ev.line) st.target = String(ev.line).slice(0, 40); app.requestApps(); }
    else if (ev.cmd === 'apps') st.apps = ev.installed;
    else if (ev.cmd === 'pointer') { const z = zoneAt(ev.y), h = z ? z.i : -1; if (h === st.hover) continue; st.hover = h; }
    else if (ev.cmd === 'button' && ev.pressed && ev.button === 'left') {
      const z = zoneAt(ev.y), r = z && rows()[z.i];
      if (r) app.requestOpen(st.target, r.mode, r.id);
      continue;
    } else if (ev.cmd !== 'look' && ev.cmd !== 'focus') continue;
    draw();
  }
})();

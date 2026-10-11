'use strict';
// System widget: CPU, memory, load and uptime, live.
const path = require('path');
const { App, Canvas } = require(process.env.KOS_SDK_JS);
const dir = path.dirname(process.env.KOS_SDK_JS);
const G = require(path.join(dir, 'gfx.js'));
const K = require(path.join(dir, 'kit.js'));

(async () => {
  const app = new App();
  const hist = new K.History(60);
  const st = { d: null, cpu: 0, prev: null, n: 0 };
  const meter = (c, x, y, w, h, frac, label, value, base) => {
    G.stext(c, app, x, y - 2 * app.scale, label, '#cfe3ff', 6 * app.scale + 1, 1);
    const bx = x + 26 * app.scale, bw = w - 26 * app.scale - 4 * app.scale;
    G.roundRect(c, bx, y - 1, bw, h, Math.round(h / 2), '#101318');
    G.roundRect(c, bx + 1, y, Math.max(h - 2, Math.round((bw - 2) * Math.min(1, frac))), h - 2, Math.round((h - 2) / 2), base);
    G.stext(c, app, bx + 6 * app.scale, y - 1 * app.scale, value, '#ffffff', 6 * app.scale + 1, 1);
  };
  const draw = () => {
    const c = new Canvas(), u = app.scale, W = app.width, d = st.d;
    if (!d) return app.present(c);
    const m = d.mem_kb, used = m.MemTotal - m.MemAvailable;
    meter(c, 8 * u, 7 * u, W - 16 * u, 11 * u, st.cpu, 'CPU', K.pct(st.cpu), G.ACCENT);
    meter(c, 8 * u, 22 * u, W - 16 * u, 11 * u, used / m.MemTotal, 'MEM', `${K.kb(used)}`, '#4aa3df');
    const gh = 14 * u, gx = 8 * u, gw = W - 16 * u, top = 38 * u;
    G.roundRect(c, gx, top, gw, gh, 3 * u, '#101318');
    for (let i = 0; i < hist.v.length; i++) {
      const h = Math.max(1, Math.round(hist.v[i] * (gh - 2)));
      c.rect(gx + 1 + Math.round(i * (gw - 2) / 60), top + gh - 1 - h, Math.max(1, Math.round((gw - 2) / 60)), h, '#4cc2ff');
    }
    G.stext(c, app, 8 * u, top + gh + 3 * u, `Load ${d.load[0].toFixed(2)}    Up ${K.dur(d.uptime)}    ${d.cpus} cores`, '#dbe7f5', 6 * u + 1);
    app.present(c);
  };
  for await (const ev of app.events()) {
    if (ev.cmd === 'hello') app.requestSys('resources');
    else if (ev.cmd === 'tick') { app.requestSys('resources'); continue; }
    else if (ev.cmd === 'sys' && ev.kind === 'resources') {
      const d = ev.data, total = d.cpu_ticks.reduce((a, b) => a + b, 0), idle = (d.cpu_ticks[3] || 0) + (d.cpu_ticks[4] || 0);
      if (st.prev && total > st.prev.total) st.cpu = 1 - (idle - st.prev.idle) / (total - st.prev.total);
      st.prev = { total, idle }; hist.push(st.cpu); st.d = d;
    } else continue;
    draw();
  }
})();

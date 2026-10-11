'use strict';
// Calendar widget: this month, today highlighted. Weeks start on Monday.
const path = require('path');
const { App, Canvas } = require(process.env.KOS_SDK_JS);
const G = require(path.join(path.dirname(process.env.KOS_SDK_JS), 'gfx.js'));
const MONTHS = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];

(async () => {
  const app = new App();
  let lastDay = '';
  for await (const ev of app.events()) {
    if (ev.cmd === 'hello') { lastDay = ''; continue; }      // re-attached: redraw on the next tick
    if (ev.cmd !== 'tick') continue;
    const l = ev.local; if (!l) continue;
    const key = `${l.year}-${l.month}-${l.day}`;
    if (key === lastDay) continue;
    lastDay = key;
    const c = new Canvas(), u = app.scale, W = app.width, H = app.height;
    const first = (new Date(l.year, l.month - 1, 1).getDay() + 6) % 7, days = new Date(l.year, l.month, 0).getDate();
    G.stextCentered(c, app, W / 2, 4 * u, `${MONTHS[l.month - 1]} ${l.year}`, '#ffffff', 8 * u, 1);
    const cw = Math.floor((W - 16 * u) / 7), x0 = 8 * u;
    'MTWTFSS'.split('').forEach((d, i) => G.stextCentered(c, app, x0 + i * cw + cw / 2, 18 * u, d, i > 4 ? '#ffb0a0' : '#9fd0ff', 6 * u + 1, 1));
    c.rect(x0, 29 * u, W - 16 * u, u, '#9fd0ff');
    const rh = Math.floor((H - 36 * u) / 6);
    for (let d = 1; d <= days; d++) {
      const i = first + d - 1, col = i % 7, row = Math.floor(i / 7), cx = x0 + col * cw + cw / 2, y = 32 * u + row * rh;
      if (d === l.day) {
        G.roundRect(c, Math.round(cx - cw / 2 + u), y - u, cw - 2 * u, rh - u, Math.round((rh - u) / 2), G.ACCENT);
        G.stextCentered(c, app, cx, y + Math.round((rh - 7 * u) / 2) - u, String(d), '#ffffff', 7 * u, 1, null);
      } else G.stextCentered(c, app, cx, y + Math.round((rh - 7 * u) / 2) - u, String(d), col > 4 ? '#ffb0a0' : '#ffffff', 7 * u);
    }
    app.present(c);
  }
})();

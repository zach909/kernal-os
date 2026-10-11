'use strict';
// Clock widget: an analog dial (hands drawn as lines) and the digital time and date.
const path = require('path');
const { App, Canvas } = require(process.env.KOS_SDK_JS);
const G = require(path.join(path.dirname(process.env.KOS_SDK_JS), 'gfx.js'));
const DAYS = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const two = (n) => String(n).padStart(2, '0');

(async () => {
  const app = new App();
  let last = -1;
  for await (const ev of app.events()) {
    if (ev.cmd === 'hello') { last = -1; continue; }
    if (ev.cmd !== 'tick') continue;
    const l = ev.local; if (!l) continue;
    if (l.second === last) continue;
    last = l.second;
    const c = new Canvas(), u = app.scale, H = app.height;
    const r = Math.round(H / 2 - 7 * u), cx = r + 10 * u, cy = Math.round(H / 2);
    G.circle(c, cx, cy + u, r, '#000000');
    G.ring(c, cx, cy, r, '#ffffff'); G.ring(c, cx, cy, r - 1, '#9fd0ff');
    for (let i = 0; i < 12; i++) {
      const a = (i / 12) * 2 * Math.PI - Math.PI / 2, r0 = r - (i % 3 === 0 ? 5 * u : 3 * u);
      c.line(Math.round(cx + r0 * Math.cos(a)), Math.round(cy + r0 * Math.sin(a)), Math.round(cx + (r - 1) * Math.cos(a)), Math.round(cy + (r - 1) * Math.sin(a)), '#ffffff');
    }
    const hand = (frac, len, col) => { const a = frac * 2 * Math.PI - Math.PI / 2; c.line(cx, cy, Math.round(cx + len * Math.cos(a)), Math.round(cy + len * Math.sin(a)), col); };
    hand(((l.hour % 12) + l.minute / 60) / 12, r * 0.5, '#ffffff'); hand((l.minute + l.second / 60) / 60, r * 0.78, '#cfe0ff'); hand(l.second / 60, r * 0.88, '#4cc2ff');
    G.circle(c, cx, cy, Math.max(1, u), '#4cc2ff');
    const x = cx + r + 10 * u;
    const big = 19 * u, hm = `${two(l.hour)}:${two(l.minute)}`;
    G.stext(c, app, x, Math.round(H / 2 - 25 * u), hm, '#ffffff', big, 1);
    G.stext(c, app, x + app.textWidth(hm, big, 1) + 3 * u, Math.round(H / 2 - 17 * u), two(l.second), '#4cc2ff', 9 * u, 1);
    G.stext(c, app, x, Math.round(H / 2 + 3 * u), DAYS[l.weekday], '#ffffff', 8 * u, 1);
    G.stext(c, app, x, Math.round(H / 2 + 15 * u), `${l.day} ${MONTHS[l.month - 1]} ${l.year}`, '#dbe7f5', 7 * u);
    app.present(c);
  }
})();

'use strict';
// Encryption: is everything encrypted? One row per layer - disk, swap, RAM, scratch space, core dumps, hibernation, secrets in memory,
// off-site backups - with a plain yes / partly / unknown / NO and what to do about it. KOS writes no cipher of its own: it uses what the
// kernel and the CPU provide and says so when they are not switched on. Software cannot encrypt RAM; only the CPU can.
const path = require('path');
const { App, Canvas } = require(process.env.KOS_SDK_JS);
const G = require(path.join(path.dirname(process.env.KOS_SDK_JS), 'gfx.js'));
const COLOR = { ok: '#3fb27f', partial: '#e0b341', unknown: '#7fa9d8', no: '#e0624f' };
const WORD = { ok: 'yes', partial: 'partly', unknown: 'unknown', no: 'NO' };
(async () => {
  const app = new App();
  const st = { items: [], tick: 0 };
  const draw = () => {
    G.setLook(app.look);
    const c = new Canvas(), u = app.scale, W = app.width, H = app.height, px = 6 * u + 1;
    G.stext(c, app, 16 * u, 8 * u, 'Is everything encrypted?', '#ffffff', 11 * u, 1);
    G.stext(c, app, 16 * u, 24 * u, 'Layer by layer. KOS uses what the kernel and the CPU provide and says when it is off.', '#9fb2c8', px);
    let y = 42 * u;
    for (const i of st.items) {
      const h = i.fix && i.status !== 'ok' ? 34 * u : 24 * u;
      if (y + h > H - 6 * u) break;
      G.roundRect(c, 16 * u, y, W - 32 * u, h - 4 * u, 7 * u, '#262b34');
      c.hit(16 * u, y, W - 32 * u, h - 4 * u, `${i.layer}: ${WORD[i.status]}`);
      G.roundRect(c, 22 * u, y + 5 * u, 40 * u, 12 * u, 6 * u, COLOR[i.status] || '#4b525e');
      G.stextCentered(c, app, 42 * u, y + 6 * u, WORD[i.status] || i.status, '#0b0f16', 6 * u, 1, null);
      G.stext(c, app, 70 * u, y + 3 * u, i.layer, '#ffffff', 7 * u, 1, null);
      G.stext(c, app, 70 * u, y + 13 * u, String(i.detail).slice(0, 100), '#aab4c4', 5 * u + 1, 0, null);
      if (i.fix && i.status !== 'ok') G.stext(c, app, 70 * u, y + 22 * u, 'fix: ' + String(i.fix).slice(0, 96), '#e0b341', 5 * u + 1, 0, null);
      y += h;
    }
    app.present(c);
  };
  for await (const ev of app.events()) {
    if (ev.cmd === 'hello') app.requestEncryption();
    else if (ev.cmd === 'encryption') st.items = ev.items;
    else if (ev.cmd === 'tick') { if (++st.tick % 30 === 0) app.requestEncryption(); continue; }
    else if (ev.cmd !== 'look') continue;
    draw();
  }
})();

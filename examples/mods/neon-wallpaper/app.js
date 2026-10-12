'use strict';
// A wallpaper mod: it fills the "wallpaper" slot, asks for no permission at all, and draws the whole screen from code.
const path = require('path');
const { App, Canvas } = require(process.env.KOS_SDK_JS);
const G = require(path.join(path.dirname(process.env.KOS_SDK_JS), 'gfx.js'));

function draw(c, w, h) {
  const horizon = Math.round(h * 0.62);
  G.gradV(c, 0, 0, w, horizon, '#10122e', '#ff7a45');
  for (let i = 0; i < Math.round(w / 14); i++) c.rect((i * 2654435761) % w, (i * 40503 + 17) % Math.round(horizon * 0.6), i % 7 ? 1 : 2, i % 7 ? 1 : 2, i % 7 ? '#aab0e0' : '#ffffff');
  const R = Math.round(h * 0.17), cx = Math.round(w * 0.5), cy = horizon - Math.round(R * 0.15);
  for (let dy = -R; dy <= 0; dy++) {                                   // a sun with horizontal cut-outs
    const band = Math.floor((dy + R) / Math.max(2, Math.round(R / 9)));
    if (dy + R > R * 0.45 && band % 2 === 0) continue;
    const half = Math.round(Math.sqrt(R * R - dy * dy)), t = (dy + R) / R;
    c.rect(cx - half, cy + dy, 2 * half, 1, G.color(255, 235 - 120 * t, 130 - 90 * t));
  }
  const step = Math.max(2, Math.round(w / 320));
  for (let x = 0; x < w; x += step) {
    const far = Math.round(h * 0.05 + h * 0.06 * Math.abs(((x * 0.9) % 210) - 105) / 105 + h * 0.035 * Math.abs(((x * 2.1 + 60) % 330) - 165) / 165);
    c.rect(x, horizon - far, step, far, '#2a1148');
  }
  G.gradV(c, 0, horizon, w, h - horizon, '#1b0a33', '#07020f');
  for (let i = -16; i <= 16; i++) c.line(Math.round(w / 2 + i * w * 0.012), horizon, Math.round(w / 2 + i * w * 0.14), h, '#b445ff');
  for (let k = 1; k <= 9; k++) c.rect(0, horizon + Math.round((h - horizon) * (k / 9) ** 2), w, 1, '#b445ff');
  c.rect(0, horizon, w, 2, '#ff7ad9');
}
(async () => {
  const app = new App();
  for await (const ev of app.events()) { if (ev.cmd !== 'hello') continue; const c = new Canvas(); draw(c, app.width, app.height); app.present(c); }
})();

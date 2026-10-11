'use strict';
// Network widget: link state, address and speeds. The button asks the OS to test the
// internet (it asks for your password: that is the one thing that talks outward).
const path = require('path');
const { App, Canvas } = require(process.env.KOS_SDK_JS);
const dir = path.dirname(process.env.KOS_SDK_JS);
const G = require(path.join(dir, 'gfx.js'));
const K = require(path.join(dir, 'kit.js'));

(async () => {
  const app = new App();
  const rate = new K.Rate();
  const st = { net: null, rx: 0, tx: 0, inet: '', n: 0, hover: false };
  let btn = { x: 0, y: 0, w: 0, h: 0 };
  const draw = () => {
    const c = new Canvas(), u = app.scale, W = app.width, H = app.height;
    const link = st.net && st.net.interfaces.find((i) => i.name !== 'lo' && i.state === 'up' && i.ipv4);
    for (let i = 0; i < 4; i++) c.rect(8 * u + i * 4 * u, 22 * u - (i + 1) * 4 * u, 3 * u, (i + 1) * 4 * u, link ? '#ffffff' : '#ff6b6b');
    G.stext(c, app, 34 * u, 3 * u, link ? `${link.name}   ${link.ipv4}` : 'Not connected', '#ffffff', 8 * u, 1);
    G.stext(c, app, 34 * u, 15 * u, `Down ${K.bytes(st.rx)}/s    Up ${K.bytes(st.tx)}/s`, '#cfe3ff', 6 * u + 1);
    btn = { x: 8 * u, y: H - 17 * u, w: 56 * u, h: 13 * u };
    G.roundRect(c, btn.x, btn.y, btn.w, btn.h, Math.round(btn.h / 2), st.hover ? '#2b88d8' : G.ACCENT);
    G.stextCentered(c, app, btn.x + btn.w / 2, btn.y + Math.round((btn.h - 6 * u * 1.2) / 2), 'Check', '#ffffff', 6 * u + 1, 1);
    G.stext(c, app, btn.x + btn.w + 8 * u, btn.y + 3 * u, (st.inet || 'Not checked').slice(0, Math.floor((W - btn.w - 24 * u) / (3.4 * u))), st.inet.startsWith('No i') ? '#ffb0a0' : '#dbe7f5', 6 * u + 1);
    app.present(c);
  };
  for await (const ev of app.events()) {
    if (ev.cmd === 'hello') app.requestSys('network');
    else if (ev.cmd === 'tick') { if (++st.n % 2 === 0) app.requestSys('network'); continue; }
    else if (ev.cmd === 'sys' && ev.kind === 'network') {
      st.net = ev.data; const t = Date.now() / 1000;
      st.rx = st.tx = 0;
      for (const i of ev.data.interfaces.filter((x) => x.name !== 'lo')) { st.rx += rate.of(i.name + 'r', i.rx_bytes, t); st.tx += rate.of(i.name + 't', i.tx_bytes, t); }
    } else if (ev.cmd === 'result') st.inet = ev.ok ? `Online ${(ev.detail.match(/\((.*?)\)/) || ['', ''])[1]}` : 'No internet';
    else if (ev.cmd === 'pointer') { const h = ev.x >= btn.x && ev.x < btn.x + btn.w && ev.y >= btn.y && ev.y < btn.y + btn.h; if (h === st.hover) continue; st.hover = h; }
    else if (ev.cmd === 'button' && ev.pressed && ev.button === 'left') { if (st.hover) { st.inet = 'Password in the OS prompt'; app.requestNetCheck(); } }
    else continue;
    draw();
  }
})();

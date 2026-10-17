'use strict';
// Add-ons: features that are not part of the default system. Virtual reality, augmented reality and the neural interface reach for a
// headset, a camera or a neural device, so they are off until you turn them on - which asks for your password every time (a sudo window
// does not stand in for it). An add-on is not code loaded into the OS: it unlocks a look the compositor already draws, and the hardware side
// lives in separate sandboxed driver apps. Turning one off puts the interface back to a normal look at once.
const path = require('path');
const { App, Canvas } = require(process.env.KOS_SDK_JS);
const G = require(path.join(path.dirname(process.env.KOS_SDK_JS), 'gfx.js'));
(async () => {
  const app = new App();
  const st = { addons: [], zones: [], err: '' };
  const draw = () => {
    G.setLook(app.look);
    const c = new Canvas(), u = app.scale, W = app.width, H = app.height, px = 6 * u + 1;
    st.zones = [];
    G.stext(c, app, 16 * u, 8 * u, 'Add-ons', '#ffffff', 11 * u, 1);
    G.stext(c, app, 16 * u, 24 * u, 'Off by default. Turning one on or off asks for your password every time.', '#9fb2c8', px);
    let y = 42 * u;
    for (const a of st.addons) {
      G.roundRect(c, 16 * u, y, W - 32 * u, 40 * u, 8 * u, '#262b34');
      G.stext(c, app, 24 * u, y + 4 * u, a.title, '#ffffff', 8 * u, 1, null);
      G.stext(c, app, 24 * u, y + 18 * u, a.about.slice(0, 100), '#aab4c4', 5 * u + 1, 0, null);
      G.stext(c, app, 24 * u, y + 28 * u, a.about.length > 100 ? a.about.slice(100, 200) : '', '#aab4c4', 5 * u + 1, 0, null);
      const label = a.enabled ? 'Turn off' : 'Turn on', bw = 56 * u, bx = W - 16 * u - bw - 8 * u;
      c.hit(bx, y + 8 * u, bw, 18 * u, `${label}: ${a.title}`);
      G.roundRect(c, bx, y + 8 * u, bw, 18 * u, 9 * u, a.enabled ? '#4b525e' : G.ACCENT);
      G.stextCentered(c, app, bx + bw / 2, y + 8 * u + Math.round((18 * u - px * 1.2) / 2), label, '#ffffff', px, 1, null);
      st.zones.push({ x: bx, y: y + 8 * u, w: bw, h: 18 * u, name: a.name, enable: !a.enabled });
      y += 46 * u;
    }
    if (st.err) G.stext(c, app, 16 * u, H - 14 * u, st.err.slice(0, 90), '#ffb0a0', px);
    app.present(c);
  };
  const zoneAt = (x, y) => st.zones.find((z) => x >= z.x && x < z.x + z.w && y >= z.y && y < z.y + z.h);
  for await (const ev of app.events()) {
    if (ev.cmd === 'hello') app.requestAddons('list');
    else if (ev.cmd === 'addons') { st.addons = ev.addons; st.err = ''; }
    else if (ev.cmd === 'result' && !ev.ok) st.err = ev.detail;
    else if (ev.cmd === 'button' && ev.pressed && ev.button === 'left') { const z = zoneAt(ev.x, ev.y); if (z) { st.err = ''; app.requestAddons(z.enable ? 'enable' : 'disable', z.name); } continue; }
    else if (ev.cmd !== 'look') continue;
    draw();
  }
})();

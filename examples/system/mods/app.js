'use strict';
// System mods. A mod is an app that fills one part of the interface (the wallpaper, the pointer, the dock, ...) or adds a
// widget. Install it like any app (kos install), then enable it here: the OS asks for your password every time, because
// it changes what the desktop itself runs. Each part has a ceiling on what a mod may ask for; a mod over it cannot be
// enabled. The built-in app is never deleted: disable the mod and it comes back. Changes apply the next time the desktop starts.
const path = require('path');
const { App, Canvas } = require(process.env.KOS_SDK_JS);
const G = require(path.join(path.dirname(process.env.KOS_SDK_JS), 'gfx.js'));

(async () => {
  const app = new App();
  const st = { mods: [], zones: [], note: '', err: '', scroll: 0 };
  const draw = () => {
    const c = new Canvas(), u = app.scale, W = app.width, H = app.height, px = 6 * u + 1;
    st.zones = [];
    G.stext(c, app, 16 * u, 8 * u, 'System mods', '#ffffff', 11 * u, 1);
    G.stext(c, app, 16 * u, 24 * u, 'Apps that replace or extend a part of the interface. Enabling one asks for your password.', '#9fb2c8', px);
    let y = 42 * u;
    if (!st.mods.length) G.stext(c, app, 16 * u, y + 8 * u, 'No mods installed. Install one with: kos install my-mod.kapp  (its manifest names a "slot").', '#c3cbd6', px);
    for (const m of st.mods) {
      if (y + 30 * u > H - 16 * u) break;
      G.roundRect(c, 16 * u, y, W - 32 * u, 28 * u, 8 * u, '#262b34');
      G.stext(c, app, 24 * u, y + 4 * u, `${m.name}  ${m.version}`, '#ffffff', 7 * u + 1, 1, null);
      G.stext(c, app, 24 * u, y + 15 * u, `fills: ${m.slot}   asks for: ${m.permissions.join(', ') || 'nothing'}${m.problem ? '   - ' + m.problem : ''}`.slice(0, 90), m.problem ? '#ffb0a0' : '#aab4c4', 5 * u + 1, 0, null);
      if (!m.problem) {
        const label = m.enabled ? 'Disable' : 'Enable', bw = 48 * u;
        c.hit(W - 16 * u - bw - 8 * u, y + 6 * u, bw, 16 * u, `${label} ${m.name}`);
        G.roundRect(c, W - 16 * u - bw - 8 * u, y + 6 * u, bw, 16 * u, 8 * u, m.enabled ? '#4b525e' : G.ACCENT);
        G.stextCentered(c, app, W - 16 * u - bw / 2 - 8 * u, y + 6 * u + Math.round((16 * u - px * 1.2) / 2), label, '#ffffff', px, 1, null);
        st.zones.push({ x: W - 16 * u - bw - 8 * u, y: y + 6 * u, w: bw, h: 16 * u, name: m.name, enable: !m.enabled });
      }
      y += 32 * u;
    }
    if (st.note) G.stext(c, app, 16 * u, H - 14 * u, st.note, '#4cc2ff', px);
    if (st.err) G.stext(c, app, 16 * u, H - 26 * u, st.err.slice(0, 80), '#ffb0a0', px);
    app.present(c);
  };
  const zoneAt = (x, y) => st.zones.find((z) => x >= z.x && x < z.x + z.w && y >= z.y && y < z.y + z.h);
  for await (const ev of app.events()) {
    if (ev.cmd === 'hello') app.requestMods('list');
    else if (ev.cmd === 'mods') { st.mods = ev.mods; st.note = ev.note || ''; st.err = ''; }
    else if (ev.cmd === 'result' && !ev.ok) st.err = ev.detail;
    else if (ev.cmd === 'launch') continue;
    else if (ev.cmd === 'button' && ev.pressed && ev.button === 'left') { const z = zoneAt(ev.x, ev.y); if (z) { st.err = ''; app.requestMods(z.enable ? 'enable' : 'disable', z.name); } continue; }
    else continue;
    draw();
  }
})();

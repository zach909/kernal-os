'use strict';
// Services: the rule is that every service, system and part of KOS is an app and nothing - the OS included - has power over everything.
// This shows the TRUSTED CORE (the few parts that cannot be apps, because they launch, seal, confine and ask for the password), then
// every installed app with exactly the scopes it may ask the OS for. A warning appears if any app holds the bare "system" permission.
const path = require('path');
const { App, Canvas } = require(process.env.KOS_SDK_JS);
const G = require(path.join(path.dirname(process.env.KOS_SDK_JS), 'gfx.js'));
(async () => {
  const app = new App();
  const st = { core: [], apps: [], blanket: [], scroll: 0 };
  const draw = () => {
    G.setLook(app.look);
    const c = new Canvas(), u = app.scale, W = app.width, H = app.height, px = 6 * u + 1;
    G.stext(c, app, 16 * u, 8 * u, 'Services', '#ffffff', 11 * u, 1);
    G.stext(c, app, 16 * u, 24 * u, 'Everything is an app. These are the only parts that are not:', '#9fb2c8', px);
    let y = 40 * u;
    for (const k of st.core) {
      if (y + 24 * u > H) break;
      G.roundRect(c, 16 * u, y, W - 32 * u, 22 * u, 6 * u, '#262b34');
      c.hit(16 * u, y, W - 32 * u, 22 * u, k.part);
      G.stext(c, app, 24 * u, y + 2 * u, k.part.slice(0, 80), '#ffffff', 6 * u + 1, 1, null);
      G.stext(c, app, 24 * u, y + 12 * u, `does: ${k.does}`.slice(0, 70) + (k.cannot ? `   cannot: ${k.cannot}`.slice(0, 40) : ''), '#aab4c4', 5 * u, 0, null);
      y += 25 * u;
    }
    y += 6 * u;
    G.stext(c, app, 16 * u, y, `${st.apps.length} apps, each sandboxed, each with only these scopes:`, '#9fb2c8', px);
    y += 14 * u;
    for (const a of st.apps.slice(st.scroll)) {
      if (y + 12 * u > H) break;
      const bare = a.scopes.includes('*');
      G.stext(c, app, 20 * u, y, a.name, bare ? '#ffb0a0' : '#ffffff', 6 * u, 1, null);
      G.stext(c, app, 110 * u, y, (a.scopes.join(', ') || 'nothing') + (a.network ? '  [network]' : '') + (a.driver ? `  [driver:${a.driver}]` : ''), bare ? '#ffb0a0' : '#aab4c4', 6 * u, 0, null);
      y += 11 * u;
    }
    if (st.blanket.length) G.stext(c, app, 16 * u, H - 12 * u, 'WARNING: bare "system" permission: ' + st.blanket.join(', '), '#ffb0a0', px, 1);
    app.present(c);
  };
  for await (const ev of app.events()) {
    if (ev.cmd === 'hello') app.requestServices();
    else if (ev.cmd === 'services') { st.core = ev.core; st.apps = ev.apps; st.blanket = ev.blanket; }
    else if (ev.cmd === 'scroll') { st.scroll = Math.max(0, Math.min(Math.max(0, st.apps.length - 5), st.scroll + (ev.dy > 0 ? 3 : -3))); }
    else if (ev.cmd !== 'look') continue;
    draw();
  }
})();

'use strict';
// A widget mod: adds one more widget to the sidebar (slot "widget"). It reads the OS's own facts through the system request.
const path = require('path');
const { App, Canvas } = require(process.env.KOS_SDK_JS);
const dir = path.dirname(process.env.KOS_SDK_JS);
const G = require(path.join(dir, 'gfx.js'));
const K = require(path.join(dir, 'kit.js'));
(async () => {
  const app = new App();
  let d = null, n = 0;
  const draw = () => {
    const c = new Canvas(), u = app.scale;
    G.stext(c, app, 10 * u, 5 * u, 'Uptime', '#9fb2c8', 6 * u + 1, 1);
    if (d) {
      G.stext(c, app, 10 * u, 15 * u, K.dur(d.uptime), '#ffffff', 12 * u, 1);
      G.stext(c, app, 10 * u, 33 * u, `Load ${d.load[0].toFixed(2)}   ${d.cpus} cores`, '#dbe7f5', 6 * u + 1);
    }
    app.present(c);
  };
  for await (const ev of app.events()) {
    if (ev.cmd === 'hello') app.requestSys('resources');
    else if (ev.cmd === 'tick') { if (++n % 5 === 0) app.requestSys('resources'); continue; }
    else if (ev.cmd === 'sys' && ev.kind === 'resources') d = ev.data;
    else continue;
    draw();
  }
})();

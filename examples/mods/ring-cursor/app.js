'use strict';
// A cursor mod: fills the "cursor" slot. The OS centers this layer on the pointer; the app only draws what it looks like.
const path = require('path');
const { App, Canvas } = require(process.env.KOS_SDK_JS);
const G = require(path.join(path.dirname(process.env.KOS_SDK_JS), 'gfx.js'));
(async () => {
  const app = new App();
  let down = false;
  const draw = () => {
    const c = new Canvas(), u = app.scale, cx = Math.round(app.width / 2), cy = Math.round(app.height / 2);
    G.circle(c, cx, cy, 9 * u, '#000000');
    G.circle(c, cx, cy, 8 * u, down ? G.ACCENT : '#ffffff');
    if (!down) G.circle(c, cx, cy, 6 * u, '#00000000'.slice(0, 7));
    G.circle(c, cx, cy, down ? 3 * u : 2 * u, down ? '#ffffff' : '#000000');
    app.present(c);
  };
  for await (const ev of app.events()) {
    if (ev.cmd === 'cursor') { if (ev.down === down) continue; down = ev.down; }
    else if (ev.cmd !== 'hello') continue;
    draw();
  }
})();

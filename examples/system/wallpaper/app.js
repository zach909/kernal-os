'use strict';
// The background. It is an app like any other: it draws the whole screen from code
// (a blue sky and layered waves) and nothing else.
const path = require('path');
const { App, Canvas } = require(process.env.KOS_SDK_JS);
const G = require(path.join(path.dirname(process.env.KOS_SDK_JS), 'gfx.js'));

(async () => {
  const app = new App();
  for await (const ev of app.events()) {
    if (ev.cmd !== 'hello') continue;
    const c = new Canvas();
    G.wallpaper(c, app.width, app.height);
    app.present(c);
  }
})();

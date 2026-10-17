'use strict';
// camsim: a camera EMULATOR. It fills the wallpaper slot with a synthetic "room" (a gradient, a moving
// light and a few boxes) sent as raw pixels, the way a real camera driver would send its frames.
// Augmented reality shows the interface floating in front of whatever the wallpaper is; with a real camera
// driver in this slot that is the world behind you. This one is labelled as an emulator on screen.
//
// A real driver ("driver": "camera") would name its video node in "devices" (for example /dev/video0),
// be given exactly that node after your password, and convert the camera's frames to RGB before sending
// them. None is included, and none could be tested here.
const { App, Canvas } = require(process.env.KOS_SDK_JS);

const FW = 128, FH = 72;                              // the "sensor": small, drawn scaled up

function scene(t) {
  const px = Buffer.alloc(FW * FH * 3);
  const lx = (Math.sin(t / 1.7) * 0.4 + 0.5) * FW, ly = (Math.cos(t / 2.3) * 0.3 + 0.35) * FH;
  for (let y = 0; y < FH; y++) {
    for (let x = 0; x < FW; x++) {
      const i = (y * FW + x) * 3, wall = y < FH * 0.62;
      let r = wall ? 70 + y * 0.6 : 96 - (y - FH * 0.62) * 0.9, g = wall ? 78 + y * 0.5 : 78 - (y - FH * 0.62) * 0.8, b = wall ? 96 + y * 0.4 : 70;
      const d = Math.hypot(x - lx, (y - ly) * 1.6), glow = Math.max(0, 1 - d / 46) ** 2;
      r += glow * 150; g += glow * 140; b += glow * 90;
      if (x > FW * 0.12 && x < FW * 0.3 && y > FH * 0.34 && y < FH * 0.78) { r *= 0.55; g *= 0.6; b *= 0.7; }      // a cupboard
      if (x > FW * 0.66 && x < FW * 0.86 && y > FH * 0.5 && y < FH * 0.82) { r = r * 0.5 + 60; g = g * 0.5 + 38; b = b * 0.5 + 20; }   // a table
      px[i] = Math.min(255, r); px[i + 1] = Math.min(255, g); px[i + 2] = Math.min(255, b);
    }
  }
  return px;
}

(async () => {
  const app = new App();
  let timer = null;
  const draw = () => {
    const c = new Canvas();
    const s = Math.max(1, Math.ceil(Math.max(app.width / FW, app.height / FH)));
    c.blit(Math.round((app.width - FW * s) / 2), Math.round((app.height - FH * s) / 2), FW, FH, s, scene(Date.now() / 1000));
    c.stext(10 * app.scale, app.height - 12 * app.scale, 'camera emulator (camsim) - not a real camera', '#ffffff', 5 * app.scale + 1, 0);
    app.present(c);
  };
  for await (const ev of app.events()) {
    if (ev.cmd === 'hello' || ev.cmd === 'tick') draw();
  }
})();

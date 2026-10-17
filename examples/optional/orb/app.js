'use strict';
// A round, frameless clock. The window has no frame, shadow or body ("frame": "none"): it is exactly what is drawn here. Colours with an
// alpha ('#rrggbbaa') let the desktop show through; where nothing is drawn a click goes to whatever is behind. A `drag` rectangle is the
// handle that moves the window; the small x (a `hit`) closes it by exiting.
const { App, Canvas } = require(process.env.KOS_SDK_JS);
const two = (n) => String(n).padStart(2, '0');
const SIZE = 220;                                         // the window's size, in units of the screen scale

const disc = (cx, cy, r, n = 48) => Array.from({ length: n }, (_, i) => [cx + r * Math.cos(i * 2 * Math.PI / n), cy + r * Math.sin(i * 2 * Math.PI / n)]);

(async () => {
  const app = new App();
  let sized = false, now = null;
  for await (const ev of app.events()) {
    if (ev.cmd === 'hello' && !sized) { sized = true; app.requestResize(SIZE * app.scale, SIZE * app.scale); }
    if (ev.cmd === 'tick' && ev.local) now = ev.local;
    else if (ev.cmd === 'button' && ev.pressed && ev.button === 'left' && ev.x >= 184 * app.scale && ev.y <= 36 * app.scale) { app.exit(0); continue; }
    else if (ev.cmd !== 'hello') continue;
    const u = app.scale, c = new Canvas(), cx = 110 * u, cy = 120 * u;
    for (const [r, col] of [[100, '#4cc2ff14'], [94, '#4cc2ff1c'], [88, '#4cc2ff26']]) c.poly(disc(cx, cy, r * u), col);     // a soft glow, see-through
    c.poly(disc(cx, cy, 82 * u), '#0b1a2ccc');                                                                        // the glass of the orb
    c.poly(disc(cx, cy, 82 * u), '#4cc2ff40');
    c.poly(disc(cx, cy - 30 * u, 60 * u), '#ffffff10');                                                                // a highlight
    if (now) {
      const hm = `${two(now.hour)}:${two(now.minute)}`, big = 40 * u;
      c.stext(cx - app.textWidth(hm, big, 1) / 2, cy - 30 * u, hm, '#ffffff', big, 1);
      c.stext(cx - app.textWidth(two(now.second), 14 * u, 1) / 2, cy + 22 * u, two(now.second), '#4cc2ff', 14 * u, 1);
    }
    c.poly(disc(190 * u + 9 * u, 18 * u, 11 * u, 20), '#000000aa');                                                    // the close button
    c.poly(disc(190 * u + 9 * u, 18 * u, 9 * u, 20), '#ff5f57');
    c.stext(190 * u + 5 * u, 18 * u - 7 * u, 'x', '#ffffff', 12 * u, 1);
    c.hit(184 * u, 6 * u, 30 * u, 30 * u, 'Close');
    c.drag(0, 36 * u, 220 * u, 184 * u).drag(20 * u, 0, 160 * u, 36 * u);                                           // grab it anywhere on the disc
    app.present(c);
  }
})();

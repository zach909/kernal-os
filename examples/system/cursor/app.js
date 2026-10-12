'use strict';
// The mouse pointer, as an app. The OS keeps this app's small layer centered on the pointer and
// never sends it clicks; the app only decides what the pointer looks like. It is told where the
// pointer is moving (`cursor` events) and when a button is down, and draws:
//   - an arrow whose TIP is the hotspot (the middle of the layer), optionally turned to point the way
//     you are moving (a setting), easing back to the classic angle when you stop;
//   - in the 3D look: a shaded arrow with a drop shadow that "presses down" while a button is held.
const path = require('path');
const { App, Canvas } = require(process.env.KOS_SDK_JS);
const G = require(path.join(path.dirname(process.env.KOS_SDK_JS), 'gfx.js'));

// The arrow in its own frame: tip at (0,0), pointing toward -y ("up"), units of 1/20 of the box.
const ARROW = [[0, 0], [-6.2, 15.5], [-2.4, 13.2], [-0.3, 19.2], [2.6, 18], [0.8, 12.4], [5.6, 12.4]];
const REST = -Math.PI * 3 / 4;                     // the classic pointer: tip toward the top-left
const TAU = Math.PI * 2;
const wrap = (a) => { while (a > Math.PI) a -= TAU; while (a < -Math.PI) a += TAU; return a; };

function fillPolygon(c, pts, col) {                // even-odd scanline fill, one rect per run
  const ys = pts.map((p) => p[1]), y0 = Math.floor(Math.min(...ys)), y1 = Math.ceil(Math.max(...ys));
  for (let y = y0; y <= y1; y++) {
    const xs = [], yy = y + 0.5;
    for (let i = 0; i < pts.length; i++) {
      const a = pts[i], b = pts[(i + 1) % pts.length];
      if ((a[1] <= yy) !== (b[1] <= yy)) xs.push(a[0] + (yy - a[1]) / (b[1] - a[1]) * (b[0] - a[0]));
    }
    xs.sort((p, q) => p - q);
    for (let i = 0; i + 1 < xs.length; i += 2) c.rect(Math.round(xs[i]), y, Math.max(1, Math.round(xs[i + 1] - xs[i])), 1, col);
  }
}

(async () => {
  const app = new App();
  const st = { angle: REST, target: REST, down: false, moving: 0, animating: false, speed: 0 };
  const poly = (ox, oy, rot, scale, grow) => {
    const cx = 0, cy = 11;                         // grow around the middle of the arrow (for the outline)
    return ARROW.map(([x, y]) => {
      const gx = cx + (x - cx) * grow, gy = cy + (y - cy) * grow;
      const rx = (gx * Math.cos(rot) - gy * Math.sin(rot)) * scale, ry = (gx * Math.sin(rot) + gy * Math.cos(rot)) * scale;
      return [ox + rx, oy + ry];
    });
  };
  const draw = () => {
    const c = new Canvas(), u = app.scale, hx = app.width / 2, hy = app.height / 2;
    const a = st.angle + Math.PI / 2;               // the sprite points up (-90deg); turn it so its tip leads along `angle`
    const pressed = st.down, deep = app.look === '3d';
    const scale = u * (pressed ? 0.88 : 1);
    if (deep) fillPolygon(c, poly(hx + (pressed ? 1 : 4) * u, hy + (pressed ? 1 : 6) * u, a, scale, 1.05), '#06182a');   // shadow: farther away until pressed
    fillPolygon(c, poly(hx, hy, a, scale, 1.22), deep ? '#001b33' : '#0b0f16');                                       // outline
    if (deep) {
      const body = poly(hx, hy, a, scale, 1.0);
      fillPolygon(c, body, pressed ? '#2f8fe0' : '#ffffff');
      fillPolygon(c, poly(hx, hy, a, scale * 0.82, 0.8), pressed ? '#0078d4' : '#cfe8ff');                           // a shaded core: a solid, rounded feel
      c.line(Math.round(body[0][0]), Math.round(body[0][1]), Math.round(body[1][0]), Math.round(body[1][1]), '#ffffff');
    } else {
      fillPolygon(c, poly(hx, hy, a, scale, 1.0), pressed ? '#bcd8f2' : '#ffffff');
    }
    app.present(c);
  };
  const setAnim = (on) => { if (on !== st.animating) { st.animating = on; app.requestAnimate(on); } };
  for await (const ev of app.events()) {
    if (ev.cmd === 'hello' || ev.cmd === 'look') { /* redraw below */ }
    else if (ev.cmd === 'cursor') {
      const sp = Math.hypot(ev.dx, ev.dy);
      st.speed = sp;
      if (app.options.cursor_direction !== false && sp > 3) { st.target = Math.atan2(ev.dy, ev.dx); st.moving = Date.now(); setAnim(true); }
      else if (sp <= 3 && app.options.cursor_direction !== false && Date.now() - st.moving > 900) { st.target = REST; setAnim(true); }
      if (app.options.cursor_direction === false) { st.target = REST; }
      if (ev.down === st.down && !st.animating) continue;
      st.down = ev.down;
    } else if (ev.cmd === 'anim') {
      if (app.options.cursor_direction !== false && st.speed <= 3 && Date.now() - st.moving > 900) st.target = REST;
      const d = wrap(st.target - st.angle);
      st.angle = wrap(st.angle + d * 0.35);
      if (Math.abs(d) < 0.02) { st.angle = st.target; if (Date.now() - st.moving > 1200) setAnim(false); }
    } else continue;
    draw();
  }
})();

'use strict';
// The mouse pointer, as an app. The OS keeps this app's small layer centered on the pointer and
// never sends it clicks; the app only decides what the pointer looks like. It is told where the
// pointer is moving (`cursor` events) and when a button is down, and draws:
//   - an arrow whose TIP is the hotspot (the middle of the layer), optionally leaning the way you are
//     moving (a setting: a gentle lean, never more than about 30 degrees), easing back to the classic angle when you stop;
//   - in the 3D look: a shaded arrow with a drop shadow that "presses down" while a button is held.
const path = require('path');
const { App, Canvas } = require(process.env.KOS_SDK_JS);
const G = require(path.join(path.dirname(process.env.KOS_SDK_JS), 'gfx.js'));

// The arrow in its own frame: straight edges, tip at (0,0), classic orientation (tip toward the top-left),
// units of 1/20 of the box. Drawn as smooth (anti-aliased) shapes, not pixels.
const ARROW = [[0, 0], [0, 16.5], [4.1, 12.9], [6.9, 19.4], [9.6, 18.2], [6.9, 11.9], [12, 11.7]];
const REST = 0;                                    // rotation of the classic pointer
const TAU = Math.PI * 2;
const wrap = (a) => { while (a > Math.PI) a -= TAU; while (a < -Math.PI) a += TAU; return a; };

(async () => {
  const app = new App();
  const st = { angle: REST, target: REST, down: false, moving: 0, animating: false, speed: 0 };
  // the arrow turned by `rot` about its tip, scaled, and moved so the tip is at (ox, oy)
  const poly = (ox, oy, rot, scale) => ARROW.map(([x, y]) => [
    ox + (x * Math.cos(rot) - y * Math.sin(rot)) * scale, oy + (x * Math.sin(rot) + y * Math.cos(rot)) * scale]);
  const move = (pts, dx, dy) => pts.map(([x, y]) => [x + dx, y + dy]);
  const draw = () => {
    const c = new Canvas(), u = app.scale, hx = app.width / 2, hy = app.height / 2;
    const pressed = st.down, deep = app.look === '3d';
    const scale = u * 0.95 * (pressed ? 0.9 : 1);
    const body = poly(hx, hy, st.angle, scale);
    const lift = deep ? (pressed ? 1.2 : 4.5) * u : 1.4 * u;                       // 3D: farther from the screen until pressed
    c.poly(move(body, lift * 0.7, lift * 1.1), '#000000', deep ? (pressed ? 90 : 55) : 60);
    const r = 1.1 * u;
    for (let i = 0; i < 8; i++) c.poly(move(body, r * Math.cos(i * Math.PI / 4), r * Math.sin(i * Math.PI / 4)), deep ? '#001b33' : '#0b0f16');
    if (deep) {
      c.poly(body, pressed ? '#2f8fe0' : '#ffffff');
      // two facets: the half that faces the light is lighter, so the arrow reads as a solid with an edge
      const [tip, a, b, c3, d, e, f] = body;
      c.poly([tip, a, b, e, f], pressed ? '#0a63b5' : '#bfdcf7', pressed ? 160 : 200);
    } else {
      c.poly(body, pressed ? '#bcd8f2' : '#ffffff');
    }
    app.present(c);
  };
  const setAnim = (on) => { if (on !== st.animating) { st.animating = on; app.requestAnimate(on); } };
  for await (const ev of app.events()) {
    if (ev.cmd === 'hello' || ev.cmd === 'look') { /* redraw below */ }
    else if (ev.cmd === 'cursor') {
      const sp = Math.hypot(ev.dx, ev.dy);
      st.speed = sp;
      if (app.options.cursor_direction !== false && sp > 8) { st.target = REST + 0.5 * Math.max(-1, Math.min(1, ev.dx / 40)) ; st.moving = Date.now(); setAnim(true); }
      else if (sp <= 8 && app.options.cursor_direction !== false && Date.now() - st.moving > 900) { st.target = REST; setAnim(true); }
      if (app.options.cursor_direction === false) { st.target = REST; }
      if (ev.down === st.down && !st.animating) continue;
      st.down = ev.down;
    } else if (ev.cmd === 'anim') {
      if (app.options.cursor_direction !== false && st.speed <= 8 && Date.now() - st.moving > 900) st.target = REST;
      const d = wrap(st.target - st.angle);
      st.angle = wrap(st.angle + d * 0.18);
      if (Math.abs(d) < 0.02) { st.angle = st.target; if (Date.now() - st.moving > 1200) setAnim(false); }
    } else continue;
    draw();
  }
})();

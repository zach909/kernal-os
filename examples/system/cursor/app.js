'use strict';
// The mouse pointer, as an app. The OS keeps this app's small layer centered on the pointer and never sends it clicks; the app only
// decides what the pointer looks like. It is told where the pointer is moving (`cursor` events) and when a button is down, and draws:
//   - normal / text looks: a clean straight-edged arrow whose TIP is the hotspot (the middle of the layer), optionally leaning the way
//     you move (a setting: a gentle lean, never more than about 30 degrees);
//   - the 3D look: a solid tool - a CONE (the tip) on a CYLINDER (the shaft), shaded in two facets with a shadow. At rest it leans
//     back like a pointer; when you click it swings round to point straight DOWN at what you are pressing.
const path = require('path');
const { App, Canvas } = require(process.env.KOS_SDK_JS);
const G = require(path.join(path.dirname(process.env.KOS_SDK_JS), 'gfx.js'));

// The flat arrow: straight edges, tip at (0,0), units of 1/20 of the box.
const ARROW = [[0, 0], [0, 16.5], [4.1, 12.9], [6.9, 19.4], [9.6, 18.2], [6.9, 11.9], [12, 11.7]];
const REST = 0;                                    // lean of the flat arrow
// The 3D tool, along its own axis (+x runs from the tip back along the shaft): cone length/half-width, cylinder length/half-width.
const CONE_L = 9, CONE_R = 3.4, CYL_L = 9, CYL_R = 1.5;
const TAIL_REST = Math.PI / 4;                     // the shaft trails down and to the right: the tip points up and to the left
const TAIL_DOWN = -Math.PI / 2;                    // the shaft stands straight up: the tip points down
const TAU = Math.PI * 2;
const wrap = (a) => { while (a > Math.PI) a -= TAU; while (a < -Math.PI) a += TAU; return a; };

(async () => {
  const app = new App();
  const st = { lean: REST, leanTarget: REST, tail: TAIL_REST, down: false, moving: 0, animating: false, speed: 0 };
  const move = (pts, dx, dy) => pts.map(([x, y]) => [x + dx, y + dy]);
  // a shape given in axis coordinates, turned by `rot` about the tip, scaled, and placed with the tip at (ox, oy)
  const place = (pts, ox, oy, rot, scale) => pts.map(([x, y]) => [
    ox + (x * Math.cos(rot) - y * Math.sin(rot)) * scale, oy + (x * Math.sin(rot) + y * Math.cos(rot)) * scale]);
  const ellipse = (cx, cy, rx, ry, n = 18) => Array.from({ length: n }, (_, i) => [cx + rx * Math.cos(i * TAU / n), cy + ry * Math.sin(i * TAU / n)]);

  const drawFlat = (c, u, hx, hy, pressed) => {
    const scale = u * 0.95 * (pressed ? 0.9 : 1);
    const body = place(ARROW, hx, hy, st.lean, scale);
    c.poly(move(body, 1.0 * u, 1.5 * u), '#000000', 60);
    const r = 1.1 * u;
    for (let i = 0; i < 8; i++) c.poly(move(body, r * Math.cos(i * Math.PI / 4), r * Math.sin(i * Math.PI / 4)), '#0b0f16');
    c.poly(body, pressed ? '#bcd8f2' : '#ffffff');
  };

  const drawTool = (c, u, hx, hy, pressed) => {
    const rot = st.tail, s = u * 0.95;
    const L = CONE_L, M = CONE_L + CYL_L;
    const cone = [[0, 0], [L, -CONE_R], [L, CONE_R]];
    const cyl = [[L, -CYL_R], [M, -CYL_R], [M, CYL_R], [L, CYL_R]];
    const lift = (pressed ? 1.5 : 4.5) * u;                                   // floats above the screen until you press
    for (const [grow, alpha] of [[3, 24], [2, 30], [1, 38]]) {                // a soft shadow under both parts
      const k = grow * u * 0.6;
      c.poly(move(place(cone, hx, hy, rot, s), lift * 0.8 + k, lift * 1.2 + k), '#000000', alpha);
      c.poly(move(place(cyl, hx, hy, rot, s), lift * 0.8 + k, lift * 1.2 + k), '#000000', alpha);
    }
    const edge = '#001b33', r = 1.0 * u;
    for (let i = 0; i < 8; i++) {                                              // a dark outline: both parts, shifted around
      const dx = r * Math.cos(i * Math.PI / 4), dy = r * Math.sin(i * Math.PI / 4);
      c.poly(move(place(cone, hx, hy, rot, s), dx, dy), edge);
      c.poly(move(place(cyl, hx, hy, rot, s), dx, dy), edge);
    }
    const lit = pressed ? '#5fb2ff' : '#ffffff', shade = pressed ? '#1472cc' : '#aac9e8', cylLit = pressed ? '#3d8fe0' : '#dce9f7', cylShade = pressed ? '#0a4f9a' : '#7f9bbd';
    // the cylinder first (it is behind the cone's base): two facets and a round end
    c.poly(place([[L, -CYL_R], [M, -CYL_R], [M, 0], [L, 0]], hx, hy, rot, s), cylLit);
    c.poly(place([[L, 0], [M, 0], [M, CYL_R], [L, CYL_R]], hx, hy, rot, s), cylShade);
    c.poly(place(ellipse(M, 0, 0.55, CYL_R), hx, hy, rot, s), pressed ? '#0a4f9a' : '#5f7a9c');
    // the cone: lit on one side, shaded on the other, with a ring where it meets the shaft
    c.poly(place([[0, 0], [L, -CONE_R], [L, 0]], hx, hy, rot, s), lit);
    c.poly(place([[0, 0], [L, 0], [L, CONE_R]], hx, hy, rot, s), shade);
    c.poly(place(ellipse(L, 0, 0.7, CONE_R), hx, hy, rot, s), pressed ? '#0d5db3' : '#8fb0d3');
  };

  const draw = () => {
    const c = new Canvas(), u = app.scale, hx = app.width / 2, hy = app.height / 2;
    (app.look === '3d' ? drawTool : drawFlat)(c, u, hx, hy, st.down);
    app.present(c);
  };
  const setAnim = (on) => { if (on !== st.animating) { st.animating = on; app.requestAnimate(on); } };
  const tailTarget = () => (st.down ? TAIL_DOWN : TAIL_REST);
  for await (const ev of app.events()) {
    if (ev.cmd === 'hello' || ev.cmd === 'look') { /* redraw below */ }
    else if (ev.cmd === 'cursor') {
      const sp = Math.hypot(ev.dx, ev.dy);
      st.speed = sp;
      if (app.options.cursor_direction !== false && sp > 8) { st.leanTarget = REST + 0.5 * Math.max(-1, Math.min(1, ev.dx / 40)); st.moving = Date.now(); setAnim(true); }
      else if (sp <= 8 && app.options.cursor_direction !== false && Date.now() - st.moving > 900) { st.leanTarget = REST; setAnim(true); }
      if (app.options.cursor_direction === false) st.leanTarget = REST;
      if (ev.down !== st.down) { st.down = ev.down; setAnim(true); }          // a click: the tool swings round to point down
      else if (!st.animating) continue;
    } else if (ev.cmd === 'anim') {
      if (app.options.cursor_direction !== false && st.speed <= 8 && Date.now() - st.moving > 900) st.leanTarget = REST;
      const dl = wrap(st.leanTarget - st.lean), dt = wrap(tailTarget() - st.tail);
      st.lean = wrap(st.lean + dl * 0.18);
      st.tail = wrap(st.tail + dt * 0.35);
      if (Math.abs(dt) < 0.02) st.tail = tailTarget();
      if (Math.abs(dl) < 0.02) { st.lean = st.leanTarget; if (Math.abs(dt) < 0.02 && Date.now() - st.moving > 1200) setAnim(false); }
    } else continue;
    draw();
  }
})();

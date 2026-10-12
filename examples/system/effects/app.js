'use strict';
// Click effects. In the 3D look, a ring spreads from the click and a few small bubbles pop off it,
// rise, shrink and vanish. The OS moves this app's small layer to each click and hides it afterwards;
// the app is told about clicks (`click` events, screen coordinates), asks for animation ticks only while
// a bubble is alive, and draws nothing in the other looks.
const path = require('path');
const { App, Canvas } = require(process.env.KOS_SDK_JS);
const G = require(path.join(path.dirname(process.env.KOS_SDK_JS), 'gfx.js'));
const LIFE = 0.85;

(async () => {
  const app = new App();
  const st = { bubbles: [], t: 0, animating: false };
  const spawn = () => {
    st.t = 0;
    st.bubbles = Array.from({ length: 9 }, (_, i) => {
      const a = (i / 9) * Math.PI * 2 + Math.random() * 0.5, v = 28 + Math.random() * 38;
      return { vx: Math.cos(a) * v, vy: Math.sin(a) * v - 18, r: 2.2 + Math.random() * 3.6, life: 0.55 + Math.random() * 0.3 };
    });
  };
  const draw = () => {
    const c = new Canvas(), u = app.scale, cx = Math.round(app.width / 2), cy = Math.round(app.height / 2), t = st.t;
    if (t < LIFE) {
      const k = t / LIFE, ring = (10 + 30 * (1 - (1 - k) ** 2)) * u;
      if (k < 0.8) { G.ring(c, cx, cy, Math.round(ring), '#ffffff', 40); G.ring(c, cx, cy, Math.round(ring * 0.86), '#4cc2ff', 40); }
      for (const b of st.bubbles) {
        if (t > b.life) continue;
        const f = t / b.life, x = cx + b.vx * u * t, y = cy + (b.vy * t + 70 * t * t) * u, r = Math.max(1, Math.round(b.r * u * (1 - f * 0.7)));
        G.circle(c, Math.round(x), Math.round(y), r + 1, '#0b5aa8');
        G.circle(c, Math.round(x), Math.round(y), r, '#8fd3ff');
        G.circle(c, Math.round(x - r * 0.3), Math.round(y - r * 0.3), Math.max(1, Math.round(r * 0.4)), '#ffffff');
      }
    }
    app.present(c);
  };
  const setAnim = (on) => { if (on !== st.animating) { st.animating = on; app.requestAnimate(on); } };
  for await (const ev of app.events()) {
    if (ev.cmd === 'click') {
      if (!ev.pressed || app.look !== '3d' || app.options.bubbles === false) continue;
      spawn(); setAnim(true);
    } else if (ev.cmd === 'anim') {
      st.t += ev.dt;
      if (st.t >= LIFE) { setAnim(false); st.bubbles = []; }
    } else if (ev.cmd !== 'hello' && ev.cmd !== 'look') continue;
    draw();
  }
})();

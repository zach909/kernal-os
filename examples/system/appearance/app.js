'use strict';
// Appearance. The look of the whole interface is a setting: normal, 3D, virtual reality (one picture per eye), augmented reality (over
// a camera passthrough), neural (a scanning highlight a neural driver can drive), text (everything built from text) or terminal (a
// numbered list of every button - pick one and press Enter). Terminal is the system's own interface; every other look is an INTERFACE APP
// that draws the running apps its own way. Virtual reality, augmented reality and neural are optional interface apps: their cards appear
// once you have installed them (kos desktop install --optional interface-vr). Choosing one starts its app, which asks for your password.
// The pointer, the screen tilt and the click bubbles are options of the 3D look. The OS remembers the choice.
const path = require('path');
const { App, Canvas } = require(process.env.KOS_SDK_JS);
const G = require(path.join(path.dirname(process.env.KOS_SDK_JS), 'gfx.js'));

const LOOKS = [
  { id: 'normal', name: 'Normal', note: 'Glass, clean and flat. The default.' },
  { id: '3d', name: '3D', note: 'Everything is a solid block - windows, panels, text and icons. Look down at one: a terminal rains on top.' },
  { id: 'vr', name: 'Virtual reality', note: 'A picture for each eye, side by side, with depth. Optional app.', lock: true },
  { id: 'ar', name: 'Augmented reality', note: 'The interface floats over a camera passthrough. Optional app.', lock: true },
  { id: 'neural', name: 'Neural', note: 'A highlight scans the buttons; a neural driver picks. Optional app.', lock: true },
  { id: 'text', name: 'Text', note: 'Everything is built from text: boxes, labels and [buttons].' },
  { id: 'terminal', name: 'Terminal', note: 'No pictures. Every button in a list: Up/Down or a number, then Enter.' },
];
const OPTIONS = [
  { id: 'cursor_direction', name: 'Pointer turns to point the way you move' },
    { id: 'tilt', name: 'Screen tilts toward your movement and clicks (3D look)' },
  { id: 'bubbles', name: 'A bubble pops off every click (3D look)' },
];

(async () => {
  const app = new App();
  const st = { look: 'normal', options: {}, hover: '', zones: [] };
  const draw = () => {
    const c = new Canvas(), u = app.scale, W = app.width, H = app.height, px = 7 * u + 1;
    st.zones = [];
    G.stext(c, app, 16 * u, 10 * u, 'Appearance', '#ffffff', 11 * u, 1);
    G.stext(c, app, 16 * u, 26 * u, 'How the whole interface looks and is driven.', '#9fb2c8', 6 * u + 1);
    const cols = 4, cw = Math.floor((W - 32 * u - (cols - 1) * 8 * u) / cols), ch = 52 * u, y00 = 44 * u;
    const shown = LOOKS.filter((l) => !l.lock || (st.options.interfaces || []).includes(l.id));        // the optional looks appear once their interface app is installed
    shown.forEach((l, i) => {
      const x = 16 * u + (i % cols) * (cw + 8 * u), y0 = y00 + Math.floor(i / cols) * (ch + 8 * u);
      const on = st.look === l.id, hot = st.hover === l.id;
      c.hit(x, y0, cw, ch, `${l.name} look`);
      G.roundRect(c, x, y0, cw, ch, 8 * u, on ? G.ACCENT : hot ? '#3b4250' : '#262b34');
      G.stext(c, app, x + 8 * u, y0 + 6 * u, l.name, '#ffffff', 8 * u, 1, null);
      const words = l.note.split(' '); let line = '', ly = y0 + 20 * u;
      for (const w of words) {
        if (app.textWidth(line + ' ' + w, 5 * u + 1) > cw - 14 * u) { G.stext(c, app, x + 8 * u, ly, line, on ? '#e6f2ff' : '#aab4c4', 5 * u + 1, 0, null); line = w; ly += 8 * u; } else line = (line ? line + ' ' : '') + w;
      }
      G.stext(c, app, x + 8 * u, ly, line, on ? '#e6f2ff' : '#aab4c4', 5 * u + 1, 0, null);
      st.zones.push({ x, y: y0, w: cw, h: ch, look: l.id });
    });
    let y = y00 + Math.ceil(shown.length / cols) * (ch + 8 * u) + 8 * u;
    G.stext(c, app, 16 * u, y, 'Options', '#ffffff', 8 * u, 1);
    y += 16 * u;
    for (const o of OPTIONS) {
      const on = st.options[o.id] !== false, sx = 16 * u, sw = 26 * u, sh = 13 * u;
      c.hit(sx, y, W - 32 * u, sh, `${on ? 'Turn off' : 'Turn on'}: ${o.name}`);
      G.roundRect(c, sx, y, sw, sh, Math.round(sh / 2), on ? G.ACCENT : '#4b525e');
      G.circle(c, sx + (on ? sw - Math.round(sh / 2) : Math.round(sh / 2)), y + Math.round(sh / 2), Math.round(sh / 2) - 2 * u / 2, '#ffffff');
      G.stext(c, app, sx + sw + 8 * u, y + 1, o.name, '#e3ebf6', px, 0, null);
      st.zones.push({ x: sx, y, w: W - 32 * u, h: sh, option: o.id });
      y += 20 * u;
    }
    G.stext(c, app, 16 * u, H - 14 * u, 'Tip: in any look, Tab walks the buttons and Enter presses one.', '#9fb2c8', 5 * u + 1);
    app.present(c);
  };
  const zoneAt = (x, y) => st.zones.find((z) => x >= z.x && x < z.x + z.w && y >= z.y && y < z.y + z.h);
  for await (const ev of app.events()) {
    if (ev.cmd === 'hello') { st.look = app.look; st.options = app.options; }
    else if (ev.cmd === 'look') { st.look = ev.look; st.options = ev.options || {}; }
    else if (ev.cmd === 'launch') {
      const m = /^look-(.+)$/.exec(ev.command || '');
      if (m) { app.requestLook({ look: m[1] }); }
      continue;
    } else if (ev.cmd === 'pointer') { const z = zoneAt(ev.x, ev.y), h = z && z.look ? z.look : ''; if (h === st.hover) continue; st.hover = h; }
    else if (ev.cmd === 'button' && ev.pressed && ev.button === 'left') {
      const z = zoneAt(ev.x, ev.y);
      if (z && z.look) app.requestLook({ look: z.look });
      else if (z && z.option) app.requestLook({ [z.option]: st.options[z.option] === false });
      continue;
    } else continue;
    draw();
  }
})();

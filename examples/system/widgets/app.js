'use strict';
// The widget handler. It owns the widget dock: a strip with one button per widget. Click
// a button to show or hide that widget; click its little arrow to move it up. It does
// not draw the widgets (each is its own app) - it tells the OS how to arrange them.
const path = require('path');
const { App, Canvas } = require(process.env.KOS_SDK_JS);
const G = require(path.join(path.dirname(process.env.KOS_SDK_JS), 'gfx.js'));

const SHORT = { 'widget-clock': 'CLK', 'widget-calendar': 'CAL', 'widget-network': 'NET', 'widget-system': 'SYS' };

(async () => {
  const app = new App();
  const st = { widgets: [], order: [], hover: -1 };
  const bw = () => Math.floor(app.width / Math.max(1, st.widgets.length));
  const draw = () => {
    const c = new Canvas(), u = app.scale, H = app.height, w = bw();
    const px = 6 * u + 2;
    st.widgets.forEach((wd, i) => {
      const x = i * w, label = wd.title || wd.name, hot = st.hover === i;
      G.roundRect(c, x + 2 * u, 1, w - 4 * u, H - 2, Math.round((H - 2) / 2), wd.visible ? (hot ? '#2b88d8' : G.ACCENT) : (hot ? '#6b7280' : '#4b525e'));
      const tx = x + Math.round((w - app.textWidth(label, px, 1)) / 2) - (i > 0 ? 3 * u : 0), ty = Math.round((H - px * 1.2) / 2);
      c.stext(tx + 1, ty + 1, label, '#000000', px, 1); c.stext(tx, ty, label, wd.visible ? '#ffffff' : '#c3c9d3', px, 1);
      if (i > 0) { const ax = x + w - 10 * u, ay = Math.round(H / 2); c.line(ax, ay + 2 * u, ax + 2 * u, ay - 1, '#ffffff'); c.line(ax + 2 * u, ay - 1, ax + 4 * u, ay + 2 * u, '#ffffff'); }   // move up
    });
    app.present(c);
  };
  const act = (x) => {
    const i = Math.floor(x / bw());
    if (i < 0 || i >= st.widgets.length) return;
    const inArrow = i > 0 && x - i * bw() > bw() - 12 * app.scale;
    const order = st.widgets.map((w) => w.name);
    if (inArrow) { [order[i - 1], order[i]] = [order[i], order[i - 1]]; }
    const hidden = st.widgets.filter((w) => (inArrow ? !w.visible : (w === st.widgets[i] ? w.visible : !w.visible))).map((w) => w.name);
    app.requestLayout(order, hidden);
  };
  for await (const ev of app.events()) {
    if (ev.cmd === 'widgets') { st.widgets = ev.widgets; st.order = ev.order; }
    else if (ev.cmd === 'pointer') { const h = Math.floor(ev.x / bw()); if (h === st.hover) continue; st.hover = h; }
    else if (ev.cmd === 'button' && ev.pressed && ev.button === 'left') { act(ev.x); continue; }
    else continue;
    draw();
  }
})();

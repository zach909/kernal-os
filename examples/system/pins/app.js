'use strict';
// The desktop's pins: what you chose to put on the backdrop - apps, files, folders, web addresses. A pin is just a
// name for something (see kos/links.py): click to open it (the usual gates apply: a file asks for your password).
// The + tile pins something new: type a path, a web address or an app name, then Enter. Hover a pin for its x.
// Every installed app is in the launcher (the Super key, or the KOS menu), so the desktop stays yours.
const path = require('path');
const { App, Canvas } = require(process.env.KOS_SDK_JS);
const dir = path.dirname(process.env.KOS_SDK_JS);
const G = require(path.join(dir, 'gfx.js'));
const K = require(path.join(dir, 'kit.js'));

(async () => {
  const app = new App();
  const st = { links: [], apps: [], hover: '', zones: [], adding: false, text: '', err: '' };
  const pins = () => [...st.links.filter((l) => l.where === 'desktop'), { add: true }];
  const draw = () => {
    const c = new Canvas(), u = app.scale, W = app.width, px = 6 * u + 2;
    st.zones = [];
    const cell = { w: 78 * u, h: 76 * u }, cols = Math.max(1, Math.floor(W / cell.w));
    pins().forEach((l, i) => {
      const col = i % cols, row = Math.floor(i / cols), isz = 44 * u, x = col * cell.w + (cell.w - isz) / 2, y = row * cell.h;
      if (y + cell.h > app.height + 20 * u) return;
      if (l.add) {
        c.hit(col * cell.w, y, cell.w, cell.h, 'Pin something to the desktop');
        G.roundRect(c, Math.round(x), y, isz, isz, Math.round(isz / 4.5), st.adding ? G.ACCENT : '#3b4250');
        c.rect(Math.round(x + isz / 2 - u), y + 12 * u, 2 * u, isz - 24 * u, '#ffffff'); c.rect(Math.round(x + 12 * u), y + isz / 2 - u, isz - 24 * u, 2 * u, '#ffffff');
        G.stextCentered(c, app, col * cell.w + cell.w / 2, y + isz + 6 * u, 'Pin', '#ffffff', px - 1, 0, '#00305a');
        st.zones.push({ x: col * cell.w, y, w: cell.w, h: cell.h, add: true });
        return;
      }
      const hot = st.hover === l.id, icon = K.LINK_ICON[l.kind] || l.target;
      c.hit(col * cell.w, y, cell.w, cell.h, l.title);
      G.icon(c, Math.round(x), y - (hot ? 2 * u : 0), isz, icon, { hot });
      const label = l.title.length > 13 ? l.title.slice(0, 12) + '...' : l.title;
      G.stextCentered(c, app, col * cell.w + cell.w / 2, y + isz + 6 * u, label, '#ffffff', px - 1, 0, '#00305a');
      if (hot) { G.circle(c, Math.round(x + isz - 2 * u), y + 2 * u, 6 * u, '#000000'); G.circle(c, Math.round(x + isz - 2 * u), y + 2 * u, 5 * u, '#ff5f57'); st.zones.push({ x: x + isz - 8 * u, y, w: 12 * u, h: 12 * u, unpin: l.id }); }
      st.zones.push({ x: col * cell.w, y, w: cell.w, h: cell.h, open: l.id, hoverId: l.id });
    });
    if (st.adding) {
      const w = Math.min(W - 8 * u, 300 * u), x = 4 * u, y = app.height - 20 * u;
      G.roundRect(c, x, y, w, 16 * u, 8 * u, G.ACCENT); G.roundRect(c, x + u, y + u, w - 2 * u, 14 * u, 7 * u, '#0e1014');
      const msg = st.text || 'Pin: a path, a web address or an app name  (Enter, Esc)';
      let shown = msg; while (shown.length > 3 && app.textWidth(shown, px) > w - 16 * u) shown = shown.slice(1);
      G.stext(c, app, x + 8 * u, y + 3 * u, shown + (st.text ? '|' : ''), st.text ? '#ffffff' : '#7b8494', px, 0, null);
    }
    if (st.err) G.stext(c, app, 4 * u, app.height - 34 * u, st.err, '#ffd0c8', px, 1, '#3a0000');
    app.present(c);
  };
  const zoneAt = (x, y) => [...st.zones].reverse().find((z) => x >= z.x && x < z.x + z.w && y >= z.y && y < z.y + z.h);
  const stop = () => { if (st.adding) { st.adding = false; st.text = ''; app.requestKeys(false); } };
  for await (const ev of app.events()) {
    if (ev.cmd === 'hello') { app.requestApps(); app.requestLinks('list'); }
    else if (ev.cmd === 'apps') st.apps = ev.installed;
    else if (ev.cmd === 'links') st.links = ev.links;
    else if (ev.cmd === 'keys' && ev.on === false) { st.adding = false; st.text = ''; }
    else if (ev.cmd === 'result' && !ev.ok) st.err = ev.detail;
    else if (ev.cmd === 'pointer') { const z = zoneAt(ev.x, ev.y), h = z && z.hoverId ? z.hoverId : ''; if (h === st.hover) continue; st.hover = h; }
    else if (ev.cmd === 'button' && ev.pressed && ev.button === 'left') {
      const z = zoneAt(ev.x, ev.y); st.err = '';
      if (!z) stop();
      else if (z.unpin) app.requestLinks('remove', { id: z.unpin });
      else if (z.open) app.requestOpenLink(z.open);
      else if (z.add) { st.adding = !st.adding; st.text = ''; app.requestKeys(st.adding); }
    } else if (ev.cmd === 'key' && st.adding) {
      const k = ev.key;
      if (k === 'escape') stop();
      else if (k === 'backspace') st.text = st.text.slice(0, -1);
      else if (k === 'enter') { const link = K.parseLink(st.text, st.apps); if (link) { app.requestLinks('add', { ...link, where: 'desktop' }); stop(); } else st.err = 'That is not a path, a web address or an app'; }
      else if (k.length === 1 && k >= ' ') st.text += k;
    } else continue;
    draw();
  }
})();

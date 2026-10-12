'use strict';
// The right-hand panel. On top an segmented tab (Notifications | Widgets); in the middle either
// the notification list (drawn here) or the widgets (separate apps the OS stacks over this panel); at the
// bottom a shelf of pinned links - apps, files, folders, web addresses. Pinning only stores a name for
// something: opening a link goes through the usual gates (opening an app or viewing a file asks for your password).
const path = require('path');
const { App, Canvas } = require(process.env.KOS_SDK_JS);
const dir = path.dirname(process.env.KOS_SDK_JS);
const G = require(path.join(dir, 'gfx.js'));
const K = require(path.join(dir, 'kit.js'));
const TAB_H = 24, SHELF_H = 56;                       // in units of the UI scale; the OS uses the same numbers

(async () => {
  const app = new App();
  const st = { tab: 'widgets', notes: [], links: [], apps: [], zones: [], hover: '', adding: false, text: '', seen: 0, err: '' };
  const age = (t) => { const s = Math.max(0, Math.floor(Date.now() / 1000 - t)); return s < 60 ? 'now' : s < 3600 ? `${Math.floor(s / 60)}m` : `${Math.floor(s / 3600)}h`; };
  const wrap = (text, max, px, face = 0, lines = 2) => {
    const out = []; let line = '';
    for (const w of String(text).split(/\s+/)) {
      if (app.textWidth((line ? line + ' ' : '') + w, px, face) > max && line) { out.push(line); line = w; if (out.length === lines) break; } else line = line ? line + ' ' + w : w;
    }
    if (out.length < lines && line) out.push(line);
    return out;
  };
  const draw = () => {
    const c = new Canvas(), u = app.scale, W = app.width, H = app.height, px = 6 * u + 1;
    st.zones = [];
    // ---- the segmented tab
    const th = TAB_H * u, tx = 8 * u, tw = W - 16 * u, seg = Math.floor(tw / 2);
    G.roundRect(c, tx, 4 * u, tw, th - 8 * u, Math.round((th - 8 * u) / 2), '#262b34');
    [['notifications', `Notifications${st.notes.length ? ` (${st.notes.length})` : ''}`], ['widgets', 'Widgets']].forEach(([id, label], i) => {
      const x = tx + i * seg, on = st.tab === id;
      c.hit(x, 4 * u, seg, th - 8 * u, label);
      if (on) G.roundRect(c, x + 2 * u, 6 * u, seg - 4 * u, th - 12 * u, Math.round((th - 12 * u) / 2), G.ACCENT);
      G.stextCentered(c, app, x + seg / 2, 4 * u + Math.round(((th - 8 * u) - px * 1.2) / 2), label, on ? '#ffffff' : '#c3cbd6', px, 1, null);
      st.zones.push({ x, y: 4 * u, w: seg, h: th - 8 * u, tab: id });
    });
    // ---- notifications
    const shelfTop = H - SHELF_H * u;
    if (st.tab === 'notifications') {
      let y = th + 4 * u;
      if (!st.notes.length) G.stextCentered(c, app, W / 2, y + 20 * u, 'No notifications', '#aab4c4', 7 * u);
      else {
        c.hit(W - 52 * u, y, 44 * u, 12 * u, 'Clear all notifications');
        G.stext(c, app, W - 12 * u - app.textWidth('Clear all', px - 1), y + 1, 'Clear all', '#4cc2ff', px - 1, 1, null);
        st.zones.push({ x: W - 52 * u, y, w: 44 * u, h: 12 * u, clear: true });
        y += 14 * u;
        for (const n of [...st.notes].reverse()) {
          const body = wrap(n.body, W - 36 * u, px - 1), h = (22 + body.length * 8) * u;
          if (y + h > shelfTop - 4 * u) break;
          G.roundRect(c, 8 * u, y, W - 16 * u, h, 8 * u, '#262b34');
          c.hit(8 * u, y, W - 16 * u, h, `Dismiss: ${n.title || n.app}`);
          G.stext(c, app, 16 * u, y + 4 * u, (n.title || n.app).slice(0, 28), '#ffffff', px, 1, null);
          G.stext(c, app, W - 16 * u - app.textWidth(age(n.t), px - 1), y + 5 * u, age(n.t), '#8a93a6', px - 1, 0, null);
          body.forEach((ln, i) => G.stext(c, app, 16 * u, y + (15 + i * 8) * u, ln, '#c3cbd6', px - 1, 0, null));
          st.zones.push({ x: 8 * u, y, w: W - 16 * u, h, dismiss: n.id });
          y += h + 4 * u;
        }
      }
    }
    // ---- the shelf
    G.stext(c, app, 10 * u, shelfTop + 1 * u, 'Shelf', '#9fb2c8', px - 1, 1, null);
    const tile = 24 * u, gap = 6 * u, perRow = Math.max(1, Math.floor((W - 16 * u + gap) / (tile + gap)));
    const items = [...st.links.filter((l) => l.where === 'shelf'), { add: true }];
    items.forEach((l, i) => {
      const col = i % perRow, row = Math.floor(i / perRow), x = 8 * u + col * (tile + gap), y = shelfTop + 12 * u + row * (tile + 4 * u);
      if (y + tile > H - 2 * u) return;
      if (l.add) {
        c.hit(x, y, tile, tile, 'Pin something to the shelf');
        G.roundRect(c, x, y, tile, tile, Math.round(tile / 4), st.adding ? G.ACCENT : '#3b4250');
        c.rect(x + tile / 2 - u, y + 6 * u, 2 * u, tile - 12 * u, '#ffffff'); c.rect(x + 6 * u, y + tile / 2 - u, tile - 12 * u, 2 * u, '#ffffff');
        st.zones.push({ x, y, w: tile, h: tile, add: true });
      } else {
        const icon = K.LINK_ICON[l.kind] || l.target, hot = st.hover === l.id;
        c.hit(x, y, tile, tile, l.title);
        G.icon(c, x, y - (hot ? u : 0), tile, icon, { hot });
        if (hot) { G.circle(c, x + tile - 3 * u, y + 3 * u, 4 * u, '#000000'); G.circle(c, x + tile - 3 * u, y + 3 * u, 3 * u, '#ff5f57'); st.zones.push({ x: x + tile - 7 * u, y, w: 8 * u, h: 8 * u, unpin: l.id }); }
        st.zones.push({ x, y, w: tile, h: tile, open: l.id, hoverId: l.id });
      }
    });
    if (st.adding) {
      G.roundRect(c, 6 * u, shelfTop - 20 * u, W - 12 * u, 17 * u, 8 * u, '#171a21');
      G.roundRect(c, 7 * u, shelfTop - 19 * u, W - 14 * u, 15 * u, 7 * u, '#0e1014');
      const msg = st.text ? st.text : 'a path, a web address or an app name';
      let shown = msg; while (shown.length > 3 && app.textWidth(shown, px) > W - 28 * u) shown = shown.slice(1);
      G.stext(c, app, 12 * u, shelfTop - 17 * u, shown + (st.text ? '|' : ''), st.text ? '#ffffff' : '#7b8494', px, 0, null);
    }
    if (st.err) G.stext(c, app, 10 * u, shelfTop - 32 * u, st.err.slice(0, 40), '#ffb0a0', px - 1);
    app.present(c);
  };
  const zoneAt = (x, y) => [...st.zones].reverse().find((z) => x >= z.x && x < z.x + z.w && y >= z.y && y < z.y + z.h);
  const stopAdding = () => { if (st.adding) { st.adding = false; st.text = ''; app.requestKeys(false); } };
  for await (const ev of app.events()) {
    if (ev.cmd === 'hello') { app.requestApps(); app.requestLinks('list'); st.tab = (app.options || {}).side_tab || 'widgets'; }
    else if (ev.cmd === 'tab') st.tab = ev.name;
    else if (ev.cmd === 'apps') st.apps = ev.installed;
    else if (ev.cmd === 'links') st.links = ev.links;
    else if (ev.cmd === 'notifications') { st.notes = ev.notes; }
    else if (ev.cmd === 'keys' && ev.on === false) { st.adding = false; st.text = ''; }
    else if (ev.cmd === 'launch') { if (ev.command === 'notifications') { st.tab = 'notifications'; app.requestTab('notifications'); } else if (ev.command === 'clear') app.requestNotifyClear(); continue; }
    else if (ev.cmd === 'result' && !ev.ok) st.err = ev.detail;
    else if (ev.cmd === 'pointer') { const z = zoneAt(ev.x, ev.y), h = z && z.hoverId ? z.hoverId : ''; if (h === st.hover) continue; st.hover = h; }
    else if (ev.cmd === 'button' && ev.pressed && ev.button === 'left') {
      const z = zoneAt(ev.x, ev.y); st.err = '';
      if (!z) { stopAdding(); }
      else if (z.tab) { st.tab = z.tab; app.requestTab(z.tab); }
      else if (z.clear) app.requestNotifyClear();
      else if (z.dismiss) app.requestNotifyDismiss(z.dismiss);
      else if (z.unpin) app.requestLinks('remove', { id: z.unpin });
      else if (z.open) app.requestOpenLink(z.open);
      else if (z.add) { st.adding = !st.adding; st.text = ''; app.requestKeys(st.adding); }
    } else if (ev.cmd === 'key' && st.adding) {
      const k = ev.key;
      if (k === 'escape') stopAdding();
      else if (k === 'backspace') st.text = st.text.slice(0, -1);
      else if (k === 'enter') {
        const link = K.parseLink(st.text, st.apps);
        if (link) { app.requestLinks('add', { ...link, where: 'shelf' }); stopAdding(); } else st.err = 'Not a path, web address or app';
      } else if (k.length === 1 && k >= ' ') st.text += k;
    } else continue;
    draw();
  }
})();

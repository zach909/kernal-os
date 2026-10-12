'use strict';
// Auto-update. It knows when an update is due and tells you (a notification); one click updates every app from your sources with
// one password. KOS itself always asks, and the operating system (kernel, drivers, firmware) is listed with the exact root
// command, because KOS holds no root and cannot install those. In "auto" mode, a due run happens by itself ONLY while you have a
// sudo window open that covers apps and commands - KOS never interrupts you with a prompt on its own.
const path = require('path');
const { App, Canvas } = require(process.env.KOS_SDK_JS);
const G = require(path.join(path.dirname(process.env.KOS_SDK_JS), 'gfx.js'));

(async () => {
  const app = new App();
  const st = { s: null, os: null, lines: [], busy: false, zones: [], note: '', n: 0, told: 0 };
  const draw = () => {
    const c = new Canvas(), u = app.scale, W = app.width, H = app.height, px = 6 * u + 1, s = st.s;
    st.zones = [];
    const btn = (x, y, w, h, label, on, zone) => {
      c.hit(x, y, w, h, label);
      G.roundRect(c, x, y, w, h, Math.round(h / 2), on ? G.ACCENT : '#3b4250');
      G.stextCentered(c, app, x + w / 2, y + Math.round((h - px * 1.2) / 2), label, '#ffffff', px, 1, null);
      st.zones.push({ x, y, w, h, ...zone });
    };
    G.stext(c, app, 16 * u, 8 * u, 'Updates', '#ffffff', 11 * u, 1);
    G.stext(c, app, 16 * u, 24 * u, 'Apps are updated for you. KOS itself and the OS only ever with you.', '#9fb2c8', px);
    let y = 42 * u;
    const card = (title, body, tone) => {
      G.roundRect(c, 16 * u, y, W - 32 * u, 24 * u, 8 * u, '#262b34');
      G.stext(c, app, 24 * u, y + 3 * u, title, '#ffffff', 7 * u, 1, null);
      G.stext(c, app, 24 * u, y + 14 * u, body.slice(0, 86), tone || '#aab4c4', 5 * u + 1, 0, null);
      y += 28 * u;
    };
    if (s) {
      card('Apps', s.apps_waiting ? `${s.apps_waiting} update(s) waiting from your sources` : 'Up to date as of the last check', s.apps_waiting ? '#ffd27a' : '#aab4c4');
      card('KOS itself', s.core_behind ? `${s.core_behind} commit(s) behind - update with: kos updates core (always asks)` : 'Up to date (or not a git checkout)', s.core_behind ? '#ffd27a' : '#aab4c4');
      const o = st.os, parts = o && o.counts ? Object.entries(o.counts).map(([k, n]) => `${n} ${k}`).join(', ') : '';
      card('Operating system (kernel, drivers, firmware)', !o ? 'Press Refresh to look' : parts ? `${parts} waiting. As root: ${o.apply}` : (o.note || 'Nothing waiting'), parts ? '#ffd27a' : '#aab4c4');
      y += 2 * u;
      btn(16 * u, y, 96 * u, 16 * u, st.busy ? 'Working...' : 'Update everything now', true, { run: true });
      btn(118 * u, y, 54 * u, 16 * u, 'Refresh', false, { refresh: true });
      y += 24 * u;
      G.stext(c, app, 16 * u, y, 'Automatic', '#ffffff', 8 * u, 1); y += 14 * u;
      btn(16 * u, y, 54 * u, 14 * u, s.enabled ? 'On' : 'Off', s.enabled, { set: { enabled: !s.enabled } });
      btn(76 * u, y, 60 * u, 14 * u, s.mode === 'auto' ? 'Mode: auto' : 'Mode: ask', s.mode === 'auto', { set: { mode: s.mode === 'auto' ? 'ask' : 'auto' } });
      let x = 142 * u;
      for (const h of [6, 24, 72]) { btn(x, y, 34 * u, 14 * u, `${h} h`, s.every_hours === h, { set: { every_hours: h } }); x += 38 * u; }
      y += 20 * u;
      G.stext(c, app, 16 * u, y, s.mode === 'auto' ? 'Auto: a due run happens by itself only while a sudo window (apps + commands) is open.' : 'Ask: you are told when a check is due; one click and one password does the rest.', '#9fb2c8', px - 1);
      y += 12 * u;
      if (s.last_summary) G.stext(c, app, 16 * u, y, ('Last: ' + s.last_summary).slice(0, 90), '#c3cbd6', px - 1);
    } else G.stext(c, app, 16 * u, y, 'asking the OS...', '#c3cbd6', px);
    if (st.lines.length) { let ly = H - (st.lines.length * 9 + 10) * u; for (const l of st.lines.slice(-4)) { G.stext(c, app, 16 * u, ly, l.slice(0, 90), '#dbe7f5', px - 1, 0, null); ly += 9 * u; } }
    if (st.note) G.stext(c, app, 16 * u, H - 10 * u, st.note, '#ffb0a0', px - 1);
    app.present(c);
  };
  const zoneAt = (x, y) => st.zones.find((z) => x >= z.x && x < z.x + z.w && y >= z.y && y < z.y + z.h);
  const due = () => st.s && st.s.enabled && st.s.due;
  for await (const ev of app.events()) {
    if (ev.cmd === 'hello') app.requestAutoUpdate('status');
    else if (ev.cmd === 'tick') {
      if (++st.n % 30 === 1) app.requestAutoUpdate('status');
      if (due() && !st.busy && Date.now() - st.told > 6 * 3600 * 1000) {
        st.told = Date.now();
        if (st.s.mode === 'auto') { st.busy = true; app.requestAutoUpdate('run', { scheduled: true }); }
        else app.requestNotify('Updates are due', 'Open Updates and press "Update everything now" (one password).');
      }
      continue;
    } else if (ev.cmd === 'autoupdate') {
      st.s = ev.status; st.busy = false;
      if (ev.os) st.os = ev.os;
      if ('ran' in ev) {
        if (ev.ran) { st.lines = ev.lines; st.note = ''; app.requestNotify('Updates finished', ev.lines.slice(0, 2).join(' | ').slice(0, 190)); }
        else { st.note = ev.reason; if (ev.reason) app.requestNotify('Updates are due', ev.reason + ' - open Updates to run them.'); }
      }
    } else if (ev.cmd === 'result' && !ev.ok) { st.note = ev.detail; st.busy = false; }
    else if (ev.cmd === 'launch') { if (ev.command === 'run') { st.busy = true; app.requestAutoUpdate('run'); } else app.requestAutoUpdate('refresh'); continue; }
    else if (ev.cmd === 'button' && ev.pressed && ev.button === 'left') {
      const z = zoneAt(ev.x, ev.y); if (!z) continue;
      st.note = '';
      if (z.run) { st.busy = true; app.requestAutoUpdate('run'); }
      else if (z.refresh) app.requestAutoUpdate('refresh');
      else if (z.set) app.requestAutoUpdate('set', z.set);
    } else continue;
    draw();
  }
})();

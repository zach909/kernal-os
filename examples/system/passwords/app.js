'use strict';
// Password layers. Four layers each ask for your password: the interface (optional), apps, the commands
// apps run, and the kernel. A sudo window remembers it for a few minutes - in memory only, never on disk -
// for the layers you pick. The kernel layer and anything that changes who or what is trusted always ask.
// Starting a window, or turning the interface layer off, asks for the password in the OS's own prompt.
const path = require('path');
const { App, Canvas } = require(process.env.KOS_SDK_JS);
const G = require(path.join(path.dirname(process.env.KOS_SDK_JS), 'gfx.js'));

const LAYERS = [
  { id: 'interface', name: 'Interface', note: 'Starting the desktop and its mouse and keyboard. Optional.' },
  { id: 'app', name: 'Apps', note: 'Opening, closing, installing, updating and permitting apps.' },
  { id: 'command', name: 'Commands', note: 'What a running app asks the OS to do: files, code, processes, backups.' },
  { id: 'kernel', name: 'Kernel', note: 'The admin keyboard, your password, software sources, KOS itself. Always asks.' },
];
const MINUTES = [5, 15, 30, 60];

(async () => {
  const app = new App();
  const st = { sudo: { active: false, left: 0, layers: [] }, policy: 'required', minutes: 5, layers: { interface: true, app: true, command: true }, zones: [], note: '' };
  const draw = () => {
    const c = new Canvas(), u = app.scale, W = app.width, px = 6 * u + 1;
    st.zones = [];
    const btn = (x, y, w, h, label, on, zone) => {
      c.hit(x, y, w, h, label);
      G.roundRect(c, x, y, w, h, Math.round(h / 2), on ? G.ACCENT : '#3b4250');
      G.stextCentered(c, app, x + w / 2, y + Math.round((h - px * 1.2) / 2), label, '#ffffff', px, 1, null);
      st.zones.push({ x, y, w, h, ...zone });
    };
    G.stext(c, app, 16 * u, 8 * u, 'Passwords', '#ffffff', 11 * u, 1);
    G.stext(c, app, 16 * u, 24 * u, 'Every layer asks for your password. You decide which may be remembered, and for how long.', '#9fb2c8', px);
    let y = 42 * u;
    for (const l of LAYERS) {
      const asks = l.id === 'interface' ? st.policy === 'required' : true;
      const remembered = st.sudo.active && st.sudo.layers.includes(l.id);
      G.roundRect(c, 16 * u, y, W - 32 * u, 22 * u, 8 * u, '#262b34');
      G.stext(c, app, 24 * u, y + 3 * u, l.name, '#ffffff', 7 * u + 1, 1, null);
      G.stext(c, app, 24 * u, y + 13 * u, l.note, '#aab4c4', 5 * u + 1, 0, null);
      const tag = remembered ? 'remembered' : asks ? 'asks' : 'off';
      const tw = Math.max(50 * u, app.textWidth(tag, px, 1) + 16 * u);
      if (l.id === 'interface') btn(W - 16 * u - tw - 8 * u, y + 4 * u, tw, 14 * u, tag, asks && !remembered, { policy: asks ? 'off' : 'required' });
      else { G.roundRect(c, W - 16 * u - tw - 8 * u, y + 4 * u, tw, 14 * u, 7 * u, remembered ? '#2b88d8' : '#4b525e'); G.stextCentered(c, app, W - 16 * u - tw / 2 - 8 * u, y + 4 * u + Math.round((14 * u - px * 1.2) / 2), tag, '#ffffff', px, 1, null); }
      y += 26 * u;
    }
    y += 6 * u;
    G.stext(c, app, 16 * u, y, st.sudo.active ? `Sudo window open: ${Math.floor(st.sudo.left / 60)}:${String(st.sudo.left % 60).padStart(2, '0')} left` : 'Sudo window closed', st.sudo.active ? '#4cc2ff' : '#ffffff', 8 * u, 1);
    y += 16 * u;
    let x = 16 * u;
    G.stext(c, app, x, y + 3 * u, 'For', '#9fb2c8', px); x += app.textWidth('For', px) + 8 * u;
    for (const m of MINUTES) { btn(x, y, 36 * u, 14 * u, `${m} min`, st.minutes === m, { minutes: m }); x += 40 * u; }
    y += 20 * u; x = 16 * u;
    G.stext(c, app, x, y + 3 * u, 'Covering', '#9fb2c8', px); x += app.textWidth('Covering', px) + 8 * u;
    for (const id of ['interface', 'app', 'command']) { btn(x, y, 56 * u, 14 * u, id[0].toUpperCase() + id.slice(1), st.layers[id], { layer: id }); x += 60 * u; }
    y += 22 * u;
    btn(16 * u, y, 90 * u, 16 * u, st.sudo.active ? 'Restart window' : 'Open sudo window', true, { open: true });
    if (st.sudo.active) btn(112 * u, y, 90 * u, 16 * u, 'Close it now', false, { close: true });
    if (st.note) G.stext(c, app, 16 * u, y + 22 * u, st.note, '#ffd27a', px);
    app.present(c);
  };
  const zoneAt = (x, y) => st.zones.find((z) => x >= z.x && x < z.x + z.w && y >= z.y && y < z.y + z.h);
  const startWindow = () => app.requestSudo('open', st.minutes, Object.keys(st.layers).filter((k) => st.layers[k]));
  for await (const ev of app.events()) {
    if (ev.cmd === 'hello') { app.requestSudo('status'); app.requestPolicy('get'); }
    else if (ev.cmd === 'tick') { app.requestSudo('status'); continue; }
    else if (ev.cmd === 'sudo') st.sudo = ev;
    else if (ev.cmd === 'policy') st.policy = ev.interface;
    else if (ev.cmd === 'result' && !ev.ok) st.note = ev.detail;
    else if (ev.cmd === 'launch') { if (ev.command === 'sudo-5') { st.minutes = 5; startWindow(); } else if (ev.command === 'sudo-off') app.requestSudo('close'); continue; }
    else if (ev.cmd === 'button' && ev.pressed && ev.button === 'left') {
      const z = zoneAt(ev.x, ev.y); if (!z) continue;
      if (z.policy) app.requestPolicy('set', z.policy);
      else if (z.minutes) st.minutes = z.minutes;
      else if (z.layer) st.layers[z.layer] = !st.layers[z.layer];
      else if (z.open) startWindow();
      else if (z.close) app.requestSudo('close');
      st.note = '';
    } else continue;
    draw();
  }
})();

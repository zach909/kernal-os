'use strict';
// Settings: the hub. Everything about the system is an app, so this one holds no power of its own beyond two small things: it can ask the OS
// to change the look (the 'shell' permission) and to open another app (system:apps, which still asks for your password). The top row is the
// interface: the system's own terminal and button selector, plus every interface app that is installed (normal, 3D and any optional VR, AR or
// neural interface); the cards below open the app that owns each setting or monitor.
const path = require('path');
const { App, Canvas } = require(process.env.KOS_SDK_JS);
const G = require(path.join(path.dirname(process.env.KOS_SDK_JS), 'gfx.js'));

const LOOKS = [
  ['normal', 'Normal'], ['3d', '3D'], ['vr', 'Virtual reality'], ['ar', 'Augmented reality'], ['neural', 'Neural'], ['text', 'Text'], ['terminal', 'Terminal'],
];
const SYSTEM_LOOKS = new Set(['text', 'terminal']);              // drawn by the OS itself: always there
const SECTIONS = [
  ['Look and feel', [['appearance', 'Appearance', 'Pointer, tilt, click bubbles'], ['mods', 'System mods', 'Swap the wallpaper, dock, pointer...'],
                 ['commands', 'Commands', 'What each app offers']]],
  ['Security', [['passwords', 'Passwords', 'Which layers ask, the sudo window'], ['protections', 'Permissions', 'Kernel protections, who may run'],
                ['security', 'Security Center', 'Scan, settle, the audit trail'], ['encryption', 'Encryption', 'Is everything encrypted?'],
                ['services', 'Trusted core', 'The few parts that are not apps'], ['isolation', 'Isolation', 'How each app is confined']]],
  ['Apps and updates', [['app-library', 'App Library', 'Every installed app'], ['updates', 'Updates', 'Sources and what is new'],
                        ['autoupdate', 'Auto-update', 'Keep apps current'], ['backup', 'Backup', 'Your documents, and your own GitHub']]],
  ['This machine', [['resources', 'Resources', 'CPU, memory, storage'], ['memory', 'Memory', 'RAM, cache, swap'], ['devices', 'Devices', 'Disks, inputs, drivers'],
                    ['network', 'Network', 'Interfaces and connections'], ['processes', 'Processes', 'Every task'], ['health', 'Health', 'Faults and hardware']]],
];

(async () => {
  const app = new App();
  const st = { look: 'normal', interfaces: [], hover: '', zones: [], scroll: 0, total: 0 };
  const draw = () => {
    const c = new Canvas(), u = app.scale, W = app.width, H = app.height;
    st.zones = [];
    const pad = 16 * u, gap = 8 * u;
    let y = pad - st.scroll;
    const text = (x, yy, s, col, px, bold) => { if (yy > -20 * u && yy < H) G.stext(c, app, x, yy, s, col, px, bold ? 1 : 0, null); };
    text(pad, y, 'Settings', '#ffffff', 12 * u, true); y += 18 * u;
    text(pad, y, 'Choose the interface; open any setting. Every one of these is an app, and every one asks for your password.', '#9fb2c8', 6 * u + 1); y += 20 * u;
    // the interface chips
    text(pad, y, 'Interface', '#ffffff', 8 * u, true); y += 14 * u;
    let x = pad;
    for (const [id, name] of LOOKS) {
      if (!SYSTEM_LOOKS.has(id) && !st.interfaces.includes(id)) continue;
      const w = Math.round(app.textWidth(name, 7 * u + 1, 1)) + 20 * u, h = 17 * u;
      if (x + w > W - pad) { x = pad; y += h + 6 * u; }
      const on = st.look === id, hot = st.hover === 'look:' + id;
      if (y > -h && y < H) { c.hit(x, y, w, h, `${name} interface`); G.roundRect(c, x, y, w, h, 8 * u, on ? G.ACCENT : hot ? '#3b4250' : '#262b34'); text(x + 10 * u, y + 4 * u, name, '#ffffff', 7 * u + 1, true); }
      st.zones.push({ x, y, w, h, look: id });
      x += w + 6 * u;
    }
    y += 17 * u + 4 * u;
    if (!st.interfaces.includes('vr')) { text(pad, y, 'More interfaces (virtual reality, augmented reality, neural) are optional apps: kos desktop install --optional interface-vr', '#7e8da0', 5 * u + 1); y += 12 * u; }
    y += 6 * u;
    // the cards
    const cols = Math.max(1, Math.floor((W - 2 * pad + gap) / (96 * u + gap))), cw = Math.floor((W - 2 * pad - (cols - 1) * gap) / cols), ch = 36 * u;
    for (const [title, items] of SECTIONS) {
      text(pad, y, title, '#ffffff', 8 * u, true); y += 14 * u;
      items.forEach(([id, name, note], i) => {
        const cx = pad + (i % cols) * (cw + gap), cy = y + Math.floor(i / cols) * (ch + gap), hot = st.hover === 'app:' + id;
        if (cy > -ch && cy < H) {
          c.hit(cx, cy, cw, ch, `Open ${name}`);
          G.roundRect(c, cx, cy, cw, ch, 7 * u, hot ? '#3b4250' : '#262b34');
          text(cx + 8 * u, cy + 5 * u, name, '#ffffff', 7 * u + 1, true);
          text(cx + 8 * u, cy + 20 * u, note, '#aab4c4', 5 * u + 1);
        }
        st.zones.push({ x: cx, y: cy, w: cw, h: ch, open: id });
      });
      y += Math.ceil(items.length / cols) * (ch + gap) + 6 * u;
    }
    st.total = y + st.scroll + pad;
    app.present(c);
  };
  const zoneAt = (x, y) => st.zones.find((z) => x >= z.x && x < z.x + z.w && y >= z.y && y < z.y + z.h);
  const key = (z) => (z ? (z.look ? 'look:' + z.look : 'app:' + z.open) : '');
  for await (const ev of app.events()) {
    if (ev.cmd === 'hello') { st.look = app.look; st.interfaces = (app.options || {}).interfaces || []; }
    else if (ev.cmd === 'look') { st.look = ev.look; st.interfaces = (ev.options || {}).interfaces || st.interfaces; }
    else if (ev.cmd === 'launch') { if (ev.command === 'security') { app.requestOpen('passwords', 'graphical'); } continue; }
    else if (ev.cmd === 'pointer') { const h = key(zoneAt(ev.x, ev.y)); if (h === st.hover) continue; st.hover = h; }
    else if (ev.cmd === 'scroll') { st.scroll = Math.max(0, Math.min(Math.max(0, st.total - app.height), st.scroll - ev.dy * 12)); }
    else if (ev.cmd === 'button' && ev.pressed && ev.button === 'left') {
      const z = zoneAt(ev.x, ev.y);
      if (z && z.look) app.requestLook({ look: z.look });
      else if (z && z.open) app.requestOpen(z.open, 'graphical');
      continue;
    } else continue;
    draw();
  }
})();

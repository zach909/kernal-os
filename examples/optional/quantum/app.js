'use strict';
// Quantum and photonic hardware. This lists what the machine shows (device nodes, sysfs entries, quantum random-number sources,
// PCI ids you registered), says plainly whether a driver app is installed for each, and runs an OpenQASM job through a driver. A
// driver is the only thing that touches the hardware, and only the device node it names, after your password. An EMULATOR is
// listed as one and its results say so. If there is no hardware, this says that too - it never pretends.
const path = require('path');
const { App, Canvas } = require(process.env.KOS_SDK_JS);
const G = require(path.join(path.dirname(process.env.KOS_SDK_JS), 'gfx.js'));
const BELL = 'OPENQASM 3.0;\nqubit[2] q;\nbit[2] c;\nh q[0];\ncx q[0], q[1];\nc = measure q;\n';

(async () => {
  const app = new App();
  const st = { devices: null, sel: 0, res: null, note: '', busy: false, zones: [] };
  const draw = () => {
    const c = new Canvas(), u = app.scale, W = app.width, H = app.height, px = 6 * u + 1;
    st.zones = [];
    G.stext(c, app, 16 * u, 8 * u, 'Quantum hardware', '#ffffff', 11 * u, 1);
    G.stext(c, app, 16 * u, 24 * u, 'Real devices need a driver app; KOS finds them and gives the driver that one device node.', '#9fb2c8', px);
    let y = 42 * u;
    const devs = st.devices || [];
    if (!st.devices) G.stext(c, app, 16 * u, y, 'looking...', '#c3cbd6', px);
    else if (!devs.some((d) => d.real)) { G.stext(c, app, 16 * u, y, 'No quantum or photonic hardware found on this machine.', '#ffd27a', 8 * u, 1); y += 14 * u; }
    devs.forEach((d, i) => {
      if (y + 28 * u > H - 70 * u) return;
      const on = i === st.sel;
      c.hit(16 * u, y, W - 32 * u, 26 * u, d.name);
      G.roundRect(c, 16 * u, y, W - 32 * u, 26 * u, 8 * u, on ? '#34506e' : '#262b34');
      G.stext(c, app, 24 * u, y + 3 * u, d.name.slice(0, 60), '#ffffff', 7 * u, 1, null);
      const drv = d.drivers.length ? `driver: ${d.drivers.join(', ')}` : 'no driver installed';
      G.stext(c, app, 24 * u, y + 15 * u, `${d.real ? 'HARDWARE' : 'EMULATOR - not hardware'}   ${d.node || ''}   ${drv}`.slice(0, 90), d.real ? (d.drivers.length ? '#8fd99a' : '#ffd27a') : '#9fb2c8', 5 * u + 1, 0, null);
      st.zones.push({ x: 16 * u, y, w: W - 32 * u, h: 26 * u, sel: i });
      y += 30 * u;
    });
    const by = H - 62 * u, canRun = devs[st.sel] && devs[st.sel].drivers.length && !st.busy;
    c.hit(16 * u, by, 110 * u, 16 * u, 'Run the Bell-state demo');
    G.roundRect(c, 16 * u, by, 110 * u, 16 * u, 8 * u, canRun ? G.ACCENT : '#4b525e');
    G.stextCentered(c, app, 16 * u + 55 * u, by + Math.round((16 * u - px * 1.2) / 2), st.busy ? 'Running...' : 'Run Bell-state demo', '#ffffff', px, 1, null);
    st.zones.push({ x: 16 * u, y: by, w: 110 * u, h: 16 * u, run: true });
    if (st.res) {
      const r = st.res, total = r.shots || 1;
      G.stext(c, app, 134 * u, by + 2 * u, `${r.emulated ? 'EMULATED' : 'HARDWARE'} - ${(r.device || r.driver).slice(0, 40)} - ${total} shots`, r.emulated ? '#ffd27a' : '#8fd99a', px, 1, null);
      let x = 16 * u;
      for (const [bits, n] of Object.entries(r.counts || {}).slice(0, 6)) {
        G.stext(c, app, x, by + 20 * u, bits, '#ffffff', px, 2, null);
        G.roundRect(c, x, by + 32 * u, 40 * u, 6 * u, 3 * u, '#262b34'); G.roundRect(c, x, by + 32 * u, Math.max(3 * u, Math.round(40 * u * n / total)), 6 * u, 3 * u, G.ACCENT);
        G.stext(c, app, x, by + 40 * u, `${Math.round(100 * n / total)}%`, '#c3cbd6', px - 1, 0, null);
        x += 50 * u;
      }
    }
    if (st.note) G.stext(c, app, 16 * u, H - 12 * u, st.note.slice(0, 95), '#ffb0a0', px - 1);
    app.present(c);
  };
  const zoneAt = (x, y) => st.zones.find((z) => x >= z.x && x < z.x + z.w && y >= z.y && y < z.y + z.h);
  const run = () => { const d = (st.devices || [])[st.sel]; if (d && d.drivers.length && !st.busy) { st.busy = true; st.note = ''; app.requestQuantum('run', { program: BELL, shots: 1024, driver: d.drivers[0], device: d.id }); } };
  for await (const ev of app.events()) {
    if (ev.cmd === 'hello') app.requestQuantum('devices');
    else if (ev.cmd === 'quantum') { st.busy = false; if (ev.devices) st.devices = ev.devices; if (ev.result) { st.res = ev.result; if (ev.result.error) st.note = ev.result.error; } }
    else if (ev.cmd === 'result' && !ev.ok) { st.busy = false; st.note = ev.detail; }
    else if (ev.cmd === 'launch') { if (ev.command === 'bell') run(); else app.requestQuantum('devices'); continue; }
    else if (ev.cmd === 'button' && ev.pressed && ev.button === 'left') { const z = zoneAt(ev.x, ev.y); if (!z) continue; if (z.run) run(); else st.sel = z.sel; }
    else continue;
    draw();
  }
})();

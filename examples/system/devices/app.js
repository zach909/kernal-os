'use strict';
// I/O devices: disks and their throughput, input devices, drivers, display, and the
// buffering/caching the kernel uses to speed all of it up.
const path = require('path');
const { App } = require(process.env.KOS_SDK_JS);
const K = require(path.join(path.dirname(process.env.KOS_SDK_JS), 'kit.js'));

const TABS = ['Disks', 'Input', 'Drivers', 'Display & cache', 'Modules'];

(async () => {
  const app = new App();
  const nav = new K.Nav(app), rate = new K.Rate();
  const st = { tab: 0, d: null, rates: {} };
  const render = () => {
    const d = st.d;
    const L = ['', '  ' + TABS.map((t, i) => (i === st.tab ? `[${i + 1} ${t}]` : ` ${i + 1} ${t} `)).join(' '), ''];
    if (!d) { L.push('  asking the OS...'); return app.screen('Devices', L, ''); }
    if (st.tab === 0) {
      if (!d.disks.length) L.push('  no block devices visible (a container or VM without /sys/block)');
      for (const x of d.disks) {
        const r = st.rates[x.name] || { r: 0, w: 0 };
        L.push(`  ${K.pad(x.name, 8)} ${K.rpad(K.bytes(x.size), 7)}  ${x.rotational ? 'HDD' : 'SSD/flash'}${x.removable ? ' removable' : ''}  ${x.model || ''}`);
        L.push(`           scheduler ${x.scheduler || '?'}   read-ahead ${x.read_ahead_kb}K   in flight ${x.in_flight}`);
        L.push(`           read ${K.rpad(K.bytes(r.r) + '/s', 9)} (${K.bytes(x.read_bytes)} total, ${x.reads} ops)   write ${K.rpad(K.bytes(r.w) + '/s', 9)} (${K.bytes(x.write_bytes)} total, ${x.writes} ops)`);
      }
    } else if (st.tab === 1) {
      for (const i of d.input) L.push(`  ${K.pad(i.name, 40)} ${i.handlers.join(' ')}`);
      if (!d.input.length) L.push('  no input devices visible');
      L.push('', '  KOS never gives a device to an app: it reads the device and sends the app commands.');
    } else if (st.tab === 2) {
      L.push('  Character drivers' + ' '.repeat(22) + 'Block drivers');
      const n = Math.max(d.drivers.char.length, d.drivers.block.length);
      for (let i = 0; i < Math.min(n, app.height - 8); i++) L.push('  ' + K.pad(d.drivers.char[i] || '', 40) + (d.drivers.block[i] || ''));
    } else if (st.tab === 3) {
      const fb = d.framebuffer;
      L.push(fb.size ? `  Display   ${fb.name} ${fb.size} at ${fb.bpp} bits per pixel` : '  Display   no framebuffer (running over a terminal)');
      L.push(`  Terminal  ${d.tty ? '/dev/tty present' : 'none'}`, '', '  Buffering and caching (RAM the kernel spends to make I/O faster)');
      const b = d.buffers_kb;
      L.push(`    page cache ${K.kb(b.Cached)}   buffers ${K.kb(b.Buffers)}`);
      L.push(`    dirty (waiting to be written) ${K.kb(b.Dirty)}   being written now ${K.kb(b.Writeback)}`);
    } else {
      L.push(d.modules.length ? '  ' + d.modules.join('  ') : '  no loadable kernel modules listed (built in, or hidden)');
    }
    app.screen('Devices', L.slice(0, app.height - 2), '1-5 tabs | q back');
  };
  let n = 0;
  for await (const ev of app.events()) {
    nav.see(ev);
    if (ev.cmd === 'hello') { app.requestApps(); app.requestSys('devices'); }
    else if (ev.cmd === 'tick') { if (++n % 2 === 0) app.requestSys('devices'); continue; }
    else if (ev.cmd === 'sys' && ev.kind === 'devices') {
      st.d = ev.data;
      const t = Date.now() / 1000;
      for (const x of ev.data.disks) st.rates[x.name] = { r: rate.of(x.name + 'r', x.read_bytes, t), w: rate.of(x.name + 'w', x.write_bytes, t) };
    } else if (ev.cmd === 'key') {
      if ('12345'.includes(ev.key) && ev.key) st.tab = Number(ev.key) - 1;
      else if (ev.key === 'q' || ev.key === 'escape') nav.back();
    }
    if (ev.cmd !== 'pointer') render();
  }
})();

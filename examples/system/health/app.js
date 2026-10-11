'use strict';
// Errors & health: hardware sensors, connectivity, apps that crashed or misbehaved,
// and security events. Stopping a faulty app asks the OS (your password).
const path = require('path');
const { App } = require(process.env.KOS_SDK_JS);
const K = require(path.join(path.dirname(process.env.KOS_SDK_JS), 'kit.js'));

(async () => {
  const app = new App();
  const nav = new K.Nav(app), cur = new K.Cursor();
  const st = { d: null, n: 0, note: '' };
  const time = (t) => new Date(t * 1000).toTimeString().slice(0, 8);
  const render = () => {
    const d = st.d;
    const L = [''];
    if (!d) { L.push('  asking the OS...'); return app.screen('Health', L, ''); }
    const worst = (d.temps.length ? Math.max(...d.temps.map((t) => t.c)) : 0);
    const issues = d.faults.length + d.exited_apps.length + d.security_events.length
      + d.links.reduce((a, l) => a + l.errors, 0) + d.disk_errors.reduce((a, x) => a + x.io_errors, 0) + (worst > 85 ? 1 : 0);
    L.push(`  Overall: ${issues === 0 ? 'HEALTHY - nothing to report' : `${issues} thing(s) worth a look`}   load ${d.load.join(' ')}`, '');
    L.push('  Hardware');
    L.push('    ' + (d.temps.length ? d.temps.slice(0, 4).map((t) => `${t.label || t.chip} ${t.c.toFixed(0)}C`).join('   ') : 'no temperature sensors visible (a VM or container)'));
    L.push('    ' + (d.power.length ? d.power.map((p) => `${p.name} ${p.status} ${p.capacity >= 0 ? p.capacity + '%' : ''}`).join('   ') : 'no battery or power supply reported'));
    L.push('    ' + (d.disk_errors.length ? d.disk_errors.map((x) => `${x.disk}: ${x.io_errors} I/O errors`).join('   ') : 'no disk error counters available'));
    L.push('  Connectivity');
    L.push('    ' + (d.links.map((l) => `${l.name} ${l.state}${l.errors ? ` (${l.errors} errors)` : ''}`).join('   ') || 'no interfaces'));
    if (d.read_only_mounts.length) L.push(`  Read-only file systems (a disk problem can force this): ${d.read_only_mounts.join(', ')}`);
    L.push('  Apps that misbehaved or stopped');
    const items = [...d.exited_apps.map((id) => ({ id, what: 'exited - its record is still here' })),
      ...d.faults.slice(-6).map((f) => ({ id: f.source.replace(/\.log$/, ''), what: `${time(f.t)} ${f.line}` }))];
    cur.clamp(items.length);
    if (!items.length) L.push('    none');
    items.slice(0, 6).forEach((it, i) => L.push((i === cur.sel ? '  > ' : '    ') + K.pad(it.id, 22) + K.fit(it.what, 60)));
    L.push('  Security events');
    if (!d.security_events.length) L.push('    none');
    for (const e of d.security_events.slice(-4)) L.push(`    ${time(e.t)} ${K.pad(e.outcome, 18)} ${e.action} ${e.target}`);
    if (st.note) L.push('', '  ' + st.note);
    app.screen('Health', L.slice(0, app.height - 2), 'x stop the selected app (password) | r refresh | q back');
  };
  let sel = () => null;
  for await (const ev of app.events()) {
    nav.see(ev);
    if (ev.cmd === 'hello') { app.requestApps(); app.requestSys('health'); }
    else if (ev.cmd === 'tick') { if (++st.n % 5 === 0) app.requestSys('health'); continue; }
    else if (ev.cmd === 'sys' && ev.kind === 'health') st.d = ev.data;
    else if (ev.cmd === 'result') { st.note = (ev.ok ? '' : 'NOT DONE: ') + ev.detail; app.requestSys('health'); }
    else if (ev.cmd === 'key') {
      const k = ev.key, n = st.d ? st.d.exited_apps.length + Math.min(6, st.d.faults.length) : 0;
      if (cur.key(k, n)) { /* moved */ }
      else if (k === 'r') app.requestSys('health');
      else if (k === 'x' && st.d) {
        const ids = [...st.d.exited_apps, ...st.d.faults.slice(-6).map((f) => f.source.replace(/\.log$/, ''))];
        const id = ids[cur.sel];
        if (id && /^[a-z][a-z0-9-]*-[0-9a-f]{6}$/.test(id)) { st.note = `asking to stop ${id}...`; app.requestClose(id); }
        else st.note = 'that entry is not a running app instance';
      } else if (k === 'q' || k === 'escape') nav.back();
    }
    if (ev.cmd !== 'pointer') render();
  }
})();

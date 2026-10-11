'use strict';
// Resource accounting: CPU, memory and storage use, per-app consumption, and priorities.
// Lowering an app's priority (so priority tasks get more) asks the OS for your password.
const path = require('path');
const { App } = require(process.env.KOS_SDK_JS);
const K = require(path.join(path.dirname(process.env.KOS_SDK_JS), 'kit.js'));

(async () => {
  const app = new App();
  const nav = new K.Nav(app), cur = new K.Cursor(), rate = new K.Rate(), cpuHist = new K.History(60);
  const st = { d: null, cpu: 0, appcpu: new Map(), prev: null, note: '' };
  const render = () => {
    const d = st.d;
    const L = [''];
    if (!d) { L.push('  asking the OS...'); return app.screen('Resources', L, ''); }
    const m = d.mem_kb, used = m.MemTotal - m.MemAvailable, disk = d.disk;
    L.push(`  CPU     ${K.bar(st.cpu, 30)} ${K.pct(st.cpu)}   ${d.cpus} core(s)   load ${d.load.join(' ')}`);
    L.push('          ' + K.spark(cpuHist.v, 60));
    L.push(`  Memory  ${K.bar(used / m.MemTotal, 30)} ${K.kb(used)} of ${K.kb(m.MemTotal)}`);
    L.push(`  Disk    ${K.bar(disk.total ? 1 - disk.free / disk.total : 0, 30)} ${K.bytes(disk.total - disk.free)} of ${K.bytes(disk.total)}   KOS state ${K.bytes(d.kos_state_bytes)}`);
    L.push(`  Uptime  ${K.dur(d.uptime)}`, '', '  KOS apps - what each one is costing   (sorted by CPU)');
    L.push('  ' + K.pad('APP', 14) + K.rpad('PID', 6) + K.rpad('CPU%', 6) + K.rpad('MEM', 8) + K.rpad('NICE', 5) + K.rpad('READ', 8) + K.rpad('WRITE', 8) + K.rpad('AGE', 8));
    const apps = d.apps.map((a) => ({ ...a, cpu: st.appcpu.get(a.pid) || 0 })).sort((a, b) => b.cpu - a.cpu);
    cur.clamp(apps.length);
    apps.slice(0, Math.max(3, app.height - 15)).forEach((a, i) => L.push((i === cur.sel ? '> ' : '  ') + K.pad(a.name, 14) +
      K.rpad(a.pid, 6) + K.rpad(a.cpu.toFixed(1), 6) + K.rpad(K.kb(a.rss_kb), 8) + K.rpad(a.nice, 5) +
      K.rpad(K.bytes(a.read_bytes), 8) + K.rpad(K.bytes(a.write_bytes), 8) + K.rpad(K.dur(a.age_s), 8)));
    if (!apps.length) L.push('    no KOS apps running');
    L.push('', '  l  give the selected app LOWER priority (+5 nice) so priority tasks get more CPU');
    if (st.note) L.push('', '  ' + st.note);
    st.apps = apps;
    app.screen('Resources', L.slice(0, app.height - 2), 'updates every second | l lower priority | q back');
  };
  for await (const ev of app.events()) {
    nav.see(ev);
    if (ev.cmd === 'hello') { app.requestApps(); app.requestSys('resources'); }
    else if (ev.cmd === 'tick') { app.requestSys('resources'); continue; }
    else if (ev.cmd === 'sys' && ev.kind === 'resources') {
      const d = ev.data, t = d.uptime;
      const total = d.cpu_ticks.reduce((a, b) => a + b, 0), idle = (d.cpu_ticks[3] || 0) + (d.cpu_ticks[4] || 0);
      if (st.prev && total > st.prev.total) st.cpu = 1 - (idle - st.prev.idle) / (total - st.prev.total);
      st.prev = { total, idle };
      cpuHist.push(st.cpu);
      for (const a of d.apps) st.appcpu.set(a.pid, rate.of(a.pid, a.cpu_ticks, t) / d.clk_tck * 100);
      st.d = d;
    } else if (ev.cmd === 'result') st.note = (ev.ok ? '' : 'NOT DONE: ') + ev.detail;
    else if (ev.cmd === 'key') {
      const k = ev.key;
      if (cur.key(k, (st.apps || []).length)) { /* moved */ }
      else if (k === 'l' && st.apps && st.apps[cur.sel]) {
        const a = st.apps[cur.sel];
        st.note = `asking to lower the priority of ${a.name}...`;
        app.requestRenice(a.pid, Math.min(19, a.nice + 5));
      } else if (k === 'q' || k === 'escape') nav.back();
    }
    if (ev.cmd !== 'pointer') render();
  }
})();

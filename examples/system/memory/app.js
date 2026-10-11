'use strict';
// Memory manager: RAM, cache, swap, paging and pressure, and who is using it.
const path = require('path');
const { App } = require(process.env.KOS_SDK_JS);
const K = require(path.join(path.dirname(process.env.KOS_SDK_JS), 'kit.js'));

(async () => {
  const app = new App();
  const nav = new K.Nav(app), rate = new K.Rate(), avail = new K.History(60);
  const st = { mem: null, procs: null, t: 0, rates: {} };
  const refresh = () => { app.requestSys('memory'); app.requestSys('processes'); };
  const render = () => {
    const m = st.mem;
    if (!m) return app.screen('Memory', ['', '  asking the OS...'], '');
    const k = m.kb, used = k.MemTotal - k.MemAvailable, swapUsed = k.SwapTotal - k.SwapFree;
    const L = ['', '  Physical memory (RAM)'];
    L.push(`    RAM   ${K.bar(used / k.MemTotal, 30)} ${K.kb(used)} used of ${K.kb(k.MemTotal)} (${K.pct(used / k.MemTotal)})`);
    L.push(`          available ${K.kb(k.MemAvailable)}   free ${K.kb(k.MemFree)}   cache+buffers ${K.kb(k.Cached + k.Buffers)}`);
    L.push(`          app memory ${K.kb(k.AnonPages)}   shared ${K.kb(k.Shmem)}   kernel slab ${K.kb(k.Slab)}   dirty ${K.kb(k.Dirty)}`);
    L.push('', '  Swap / virtual memory');
    L.push(k.SwapTotal ? `    swap  ${K.bar(swapUsed / k.SwapTotal, 30)} ${K.kb(swapUsed)} of ${K.kb(k.SwapTotal)}`
      : '    swap  none configured - when RAM runs out the kernel stops a program (OOM) instead of paging');
    L.push(`    swappiness ${m.swappiness} (0 = avoid swap, 100 = eager)   overcommit mode ${m.overcommit}   committed ${K.kb(k.Committed_AS)} / limit ${K.kb(k.CommitLimit)}`);
    L.push('', '  Paging activity (per second)');
    const r = st.rates;
    L.push(`    page faults ${(r.pgfault || 0).toFixed(0)}   major faults ${(r.pgmajfault || 0).toFixed(1)}   swapped in ${(r.pswpin || 0).toFixed(1)}   swapped out ${(r.pswpout || 0).toFixed(1)}   OOM kills so far ${m.vm.oom_kill || 0}`);
    const psi = m.pressure.memory;
    L.push(`    pressure: ${psi ? `some avg10=${psi.avg10}% (time tasks stalled waiting for memory)` : 'not reported by this kernel'}`);
    L.push('', `  Available memory over time (memory given back when programs close shows as a rise)`);
    L.push('    ' + K.spark(avail.v, 60));
    L.push('', '  Biggest users');
    for (const p of ((st.procs && st.procs.processes) || []).slice(0, Math.max(3, app.height - L.length - 6))) {
      L.push(`    ${K.rpad(K.kb(p.rss_kb), 7)} ${K.bar(p.rss_kb / k.MemTotal * 8, 12)} ${p.name} (${p.pid})`);
    }
    app.screen('Memory', L.slice(0, app.height - 2), 'updates every 2 s | q back');
  };
  let n = 0;
  for await (const ev of app.events()) {
    nav.see(ev);
    if (ev.cmd === 'hello') { app.requestApps(); refresh(); }
    else if (ev.cmd === 'tick') { if (++n % 2 === 0) refresh(); continue; }
    else if (ev.cmd === 'sys' && ev.kind === 'memory') {
      st.mem = ev.data;
      const t = Date.now() / 1000;
      for (const key of ['pgfault', 'pgmajfault', 'pswpin', 'pswpout']) st.rates[key] = rate.of(key, ev.data.vm[key] || 0, t);
      avail.push(ev.data.kb.MemAvailable);
    } else if (ev.cmd === 'sys' && ev.kind === 'processes') st.procs = ev.data;
    else if (ev.cmd === 'key' && (ev.key === 'q' || ev.key === 'escape')) nav.back();
    else if (ev.cmd === 'key' && ev.key === 'r') refresh();
    if (ev.cmd !== 'pointer') render();
  }
})();

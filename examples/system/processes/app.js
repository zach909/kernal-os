'use strict';
// Processes & scheduling. Reads the process table from the OS (no password);
// signals and priority changes are requests the OS answers only after your password.
const path = require('path');
const { App } = require(process.env.KOS_SDK_JS);
const K = require(path.join(path.dirname(process.env.KOS_SDK_JS), 'kit.js'));

const STATE = { R: 'running', S: 'sleeping', D: 'waiting on disk', Z: 'zombie', T: 'stopped', t: 'traced',
  I: 'idle', X: 'dead' };

(async () => {
  const app = new App();
  const nav = new K.Nav(app), cur = new K.Cursor(), rate = new K.Rate();
  const st = { data: null, sort: 'cpu', view: 'list', net: null, note: '', cpu: new Map(), tick: 0 };
  const refresh = () => {
    app.requestSys('processes');
    if (st.view === 'ipc') { app.requestSys('network'); app.requestApps(); }
  };
  const rows = () => {
    if (!st.data) return [];
    const r = st.data.processes.map((p) => ({ ...p, cpu: st.cpu.get(p.pid) || 0 }));
    const by = { cpu: (a, b) => b.cpu - a.cpu, mem: (a, b) => b.rss_kb - a.rss_kb,
      pid: (a, b) => a.pid - b.pid, name: (a, b) => a.name.localeCompare(b.name) }[st.sort];
    return r.sort(by);
  };
  const selected = () => rows()[cur.sel];
  const render = () => {
    const d = st.data;
    if (!d) return app.screen('Processes', ['', '  asking the OS...'], '');
    const lines = [''];
    const sts = Object.entries(d.states).map(([k, v]) => `${k}:${v}`).join(' ');
    lines.push(`  Tasks ${d.total} (${sts})   Load ${d.load.join(' ')}   CPUs ${d.cpus}   Up ${K.dur(d.uptime)}`);
    if (st.view === 'ipc') {
      lines.push('', '  Inter-process communication - how programs here talk to each other', '');
      lines.push('  KOS apps (each has a private command channel to the OS):');
      for (const i of (nav.open || [])) lines.push(`    ${K.pad(i.id, 24)} ${K.pad(i.name, 14)} ${i.mode} ${i.status}`);
      const u = (st.net && st.net.unix) || [];
      lines.push('', `  Unix-domain sockets: ${u.length} (${u.filter((x) => x.state === 'connected').length} connected)`);
      for (const s of u.filter((x) => x.path).slice(0, Math.max(3, app.height - 16))) {
        lines.push(`    ${K.pad(s.type, 9)} ${K.pad(s.state, 12)} ${s.path}`);
      }
      lines.push('', '  i back to the process list');
    } else if (st.view === 'detail' && selected()) {
      const p = selected();
      lines.push('', `  ${p.name}  (pid ${p.pid}, parent ${p.ppid}, user ${p.user})`, '');
      lines.push(`  State        ${p.state} - ${STATE[p.state] || 'other'}`);
      lines.push(`  Scheduling   priority ${p.priority}, nice ${p.nice} (higher nice = lower priority)`);
      lines.push(`  Threads      ${p.threads}`);
      lines.push(`  CPU time     ${(p.cpu_ticks / d.clk_tck).toFixed(2)}s total, ${p.cpu.toFixed(1)}% now`);
      lines.push(`  Memory       ${K.kb(p.rss_kb)} resident`);
      lines.push(`  Switches     ${p.vol_switches} voluntary (waited), ${p.invol_switches} forced (time slice ended)`);
      lines.push(`  Started      ${K.dur(d.uptime - p.start_ticks / d.clk_tck)} ago`);
      lines.push(`  Command      ${p.cmd || p.name}`, '', '  t ask to exit   k force quit   s pause   g continue   + lower priority   enter back');
    } else {
      lines.push('', '  ' + K.rpad('PID', 6) + ' ' + K.pad('USER', 8) + ' S ' + K.rpad('NI', 3) + ' ' + K.rpad('THR', 3) + ' ' +
        K.rpad('CPU%', 5) + ' ' + K.rpad('MEM', 6) + '  NAME  (sorted by ' + st.sort + ')');
      const all = rows();
      cur.clamp(all.length);
      const [a, b] = cur.window(all.length, app.height - 9);
      for (let i = a; i < b; i++) {
        const p = all[i];
        lines.push((i === cur.sel ? ' >' : '  ') + K.rpad(p.pid, 6) + ' ' + K.pad(p.user, 8) + ' ' + p.state + ' ' +
          K.rpad(p.nice, 3) + ' ' + K.rpad(p.threads, 3) + ' ' + K.rpad(p.cpu.toFixed(1), 5) + ' ' +
          K.rpad(K.kb(p.rss_kb), 6) + '  ' + p.name);
      }
      lines.push('', '  c/m/p/n sort   enter details   t k s g signals   + priority   i IPC   q back');
    }
    if (st.note) lines.push('', '  ' + st.note);
    app.screen('Processes', lines.slice(0, app.height - 2), 'acting on a process asks for your password');
  };
  for await (const ev of app.events()) {
    nav.see(ev);
    if (ev.cmd === 'hello') { app.requestApps(); refresh(); }
    else if (ev.cmd === 'launch') {
      if (ev.command === 'sort-mem') st.sort = 'mem';
      else if (ev.command === 'sort-cpu') st.sort = 'cpu';
      else if (ev.command === 'ipc') { st.view = 'ipc'; refresh(); }
    } else if (ev.cmd === 'tick') { if (++st.tick % 2 === 0) refresh(); continue; }
    else if (ev.cmd === 'sys' && ev.kind === 'processes') {
      st.data = ev.data;
      for (const p of ev.data.processes) st.cpu.set(p.pid, rate.of(p.pid, p.cpu_ticks, ev.data.uptime) / ev.data.clk_tck * 100);
    } else if (ev.cmd === 'sys' && ev.kind === 'network') st.net = ev.data;
    else if (ev.cmd === 'result') { st.note = (ev.ok ? '' : 'NOT DONE: ') + ev.detail; refresh(); }
    else if (ev.cmd === 'key') {
      const k = ev.key, p = selected();
      if (st.view === 'detail') {
        if (k === 'enter' || k === 'escape') st.view = 'list';
      } else if (k === 'i') { st.view = st.view === 'ipc' ? 'list' : 'ipc'; refresh(); }
      else if (st.view === 'ipc') { if (k === 'escape') st.view = 'list'; }
      else if (cur.key(k, rows().length)) { /* moved */ }
      else if (k === 'enter' && p) st.view = 'detail';
      else if ('cmpn'.includes(k) && k.length === 1) st.sort = { c: 'cpu', m: 'mem', p: 'pid', n: 'name' }[k];
      else if (p && ['t', 'k', 's', 'g'].includes(k)) {
        st.note = `asking to ${{ t: 'TERM', k: 'KILL', s: 'STOP', g: 'CONT' }[k]} ${p.name} (${p.pid}) - password in the OS prompt`;
        app.requestSignal(p.pid, { t: 'TERM', k: 'KILL', s: 'STOP', g: 'CONT' }[k]);
      } else if (p && k === '+') {
        st.note = `asking to lower the priority of ${p.name}...`;
        app.requestRenice(p.pid, Math.min(19, p.nice + 1));
      } else if (k === 'q' || k === 'escape') nav.back();
    }
    if (ev.cmd !== 'pointer') render();
  }
})();

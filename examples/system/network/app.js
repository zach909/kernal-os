'use strict';
// Networking: interfaces, protocols, connections, local IPC sockets, and an internet
// check (the only thing here that talks to the outside, so it asks for your password).
const path = require('path');
const { App } = require(process.env.KOS_SDK_JS);
const K = require(path.join(path.dirname(process.env.KOS_SDK_JS), 'kit.js'));

const TABS = ['Interfaces', 'Protocols', 'Connections', 'IPC sockets'];
const FILTERS = ['ALL', 'ESTABLISHED', 'LISTEN'];

(async () => {
  const app = new App();
  const nav = new K.Nav(app), rate = new K.Rate(), cur = new K.Cursor();
  const st = { tab: 0, d: null, rates: {}, filter: 0, inet: 'not checked yet - press c', n: 0 };
  const render = () => {
    const d = st.d;
    const L = ['', '  ' + TABS.map((t, i) => (i === st.tab ? `[${i + 1} ${t}]` : ` ${i + 1} ${t} `)).join(' ')];
    if (!d) { L.push('', '  asking the OS...'); return app.screen('Network', L, ''); }
    L.push(`  host ${d.hostname}   gateway ${d.gateway || 'none'}   dns ${d.dns.join(', ') || 'none'}`, `  internet: ${st.inet}`, '');
    if (st.tab === 0) {
      for (const i of d.interfaces) {
        const r = st.rates[i.name] || { rx: 0, tx: 0 };
        L.push(`  ${K.pad(i.name, 8)} ${K.pad(i.state, 8)} ${K.pad(i.ipv4 || '-', 16)} ${i.mac}  mtu ${i.mtu}`);
        L.push(`           down ${K.rpad(K.bytes(r.rx) + '/s', 9)}  up ${K.rpad(K.bytes(r.tx) + '/s', 9)}   total ${K.bytes(i.rx_bytes)} in, ${K.bytes(i.tx_bytes)} out   errors ${i.rx_errors + i.tx_errors}  dropped ${i.rx_drop + i.tx_drop}`);
      }
    } else if (st.tab === 1) {
      for (const [proto, c] of Object.entries(d.protocols)) {
        L.push(`  ${proto}   ` + Object.entries(c).map(([k, v]) => `${k} ${v}`).join('   '));
      }
      L.push('', '  IP moves packets between machines; TCP adds delivery guarantees; UDP does not.');
    } else if (st.tab === 2) {
      const f = FILTERS[st.filter];
      const rows = d.connections.filter((c) => f === 'ALL' || c.state === f);
      cur.clamp(rows.length);
      L.push(`  ${rows.length} shown (filter: ${f}, f to change)`, '  ' + K.pad('PROTO', 6) + K.pad('LOCAL', 24) + K.pad('REMOTE', 24) + 'STATE');
      const [a, b] = cur.window(rows.length, app.height - 12);
      for (let i = a; i < b; i++) L.push((i === cur.sel ? ' >' : '  ') + K.pad(rows[i].proto, 6) + K.pad(rows[i].local, 24) + K.pad(rows[i].remote, 24) + rows[i].state);
    } else {
      L.push('  Local sockets programs use to talk to each other (IPC), not the network', '');
      const u = d.unix.filter((x) => x.path);
      cur.clamp(u.length);
      const [a, b] = cur.window(u.length, app.height - 12);
      for (let i = a; i < b; i++) L.push((i === cur.sel ? ' >' : '  ') + K.pad(u[i].type, 10) + K.pad(u[i].state, 13) + u[i].path);
      L.push('', `  ${d.unix.length} total, ${d.unix.length - u.length} unnamed`);
    }
    app.screen('Network', L.slice(0, app.height - 2), '1-4 tabs | c check internet (password) | q back');
  };
  for await (const ev of app.events()) {
    nav.see(ev);
    if (ev.cmd === 'hello') { app.requestApps(); app.requestSys('network'); }
    else if (ev.cmd === 'tick') { if (++st.n % 2 === 0) app.requestSys('network'); continue; }
    else if (ev.cmd === 'sys' && ev.kind === 'network') {
      st.d = ev.data;
      const t = Date.now() / 1000;
      for (const i of ev.data.interfaces) st.rates[i.name] = { rx: rate.of(i.name + 'rx', i.rx_bytes, t), tx: rate.of(i.name + 'tx', i.tx_bytes, t) };
    } else if (ev.cmd === 'result') st.inet = `${ev.ok ? 'OK' : 'NO'} - ${ev.detail} (${new Date().toTimeString().slice(0, 8)})`;
    else if (ev.cmd === 'key') {
      const k = ev.key;
      if ('1234'.includes(k) && k) { st.tab = Number(k) - 1; cur.sel = 0; }
      else if (k === 'f') st.filter = (st.filter + 1) % FILTERS.length;
      else if (k === 'c') { st.inet = 'checking - type your password in the OS prompt'; app.requestNetCheck(); }
      else if (cur.key(k, 9999)) { /* scroll */ }
      else if (k === 'q' || k === 'escape') nav.back();
    }
    if (ev.cmd !== 'pointer') render();
  }
})();

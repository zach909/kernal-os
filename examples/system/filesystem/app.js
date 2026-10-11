'use strict';
// File systems & permissions: what is mounted, how full, and who may read/write/run
// what - plus safe changes (make folder, trash, rename, chmod). Changes need the
// administrator keyboard and your password; delete moves to the trash.
const path = require('path');
const { App } = require(process.env.KOS_SDK_JS);
const K = require(path.join(path.dirname(process.env.KOS_SDK_JS), 'kit.js'));

const explain = (s) => {
  const [o, g, w] = [s.slice(1, 4), s.slice(4, 7), s.slice(7, 10)];
  const who = (x) => `${x[0] === 'r' ? 'read' : ''}${x[1] === 'w' ? ' write' : ''}${x[2] !== '-' ? ' run' : ''}`.trim() || 'nothing';
  return [`owner may ${who(o)}`, `group may ${who(g)}`, `everyone else may ${who(w)}`];
};

(async () => {
  const app = new App();
  const nav = new K.Nav(app), cur = new K.Cursor();
  const st = { tab: 1, mounts: null, path: '/', entries: [], stat: null, note: '', prompt: null, confirm: false };
  const join = (a, b) => (a.endsWith('/') ? a : a + '/') + b;
  const sel = () => st.entries[cur.sel];
  const inspect = () => { const e = sel(); if (e) app.requestSys('stat', join(st.path, e.name)); else app.requestSys('stat', st.path); };
  const render = () => {
    const L = ['', `  1 Mounts   2 Browse & permissions${st.tab === 2 ? '   ' + st.path : ''}`, ''];
    if (st.tab === 1) {
      L.push('  ' + K.pad('MOUNT', 20) + K.pad('TYPE', 9) + K.pad('SIZE', 7) + K.pad('USED', 25) + 'FLAGS');
      for (const m of ((st.mounts && st.mounts.mounts) || []).slice(0, app.height - 8)) {
        const used = m.total ? 1 - m.free / m.total : 0;
        const flags = [m.ro && 'ro', m.nosuid && 'nosuid', m.noexec && 'noexec', m.nodev && 'nodev'].filter(Boolean).join(',');
        L.push('  ' + K.pad(m.mount, 20) + K.pad(m.type, 9) + K.pad(K.bytes(m.total), 7) + K.bar(used, 14) + ' ' + K.rpad(K.pct(used), 4) + ' ' + flags);
      }
      L.push('', '  nosuid = setuid programs ignored here   noexec = nothing can be run from here   ro = read-only');
    } else {
      const [a, b] = cur.window(st.entries.length, app.height - 15);
      for (let i = a; i < b; i++) {
        const e = st.entries[i];
        L.push((i === cur.sel ? '  > ' : '    ') + e.name + (e.kind === 'dir' ? '/' : e.kind === 'zip' ? ' (zip)' : ''));
      }
      if (!st.entries.length) L.push('    (empty)');
      const s = st.stat;
      if (s) {
        L.push('', `  ${s.mode} ${s.octal}  ${s.owner}:${s.group}  ${K.bytes(s.size)}${s.entries != null ? `  ${s.entries} items` : ''}`);
        L.push('  ' + explain(s.mode).join(', '));
        L.push(`  you (${s.can_read ? 'r' : '-'}${s.can_write ? 'w' : '-'}${s.can_exec ? 'x' : '-'})` +
          (s.setuid ? '  WARNING: setuid - runs with its owner\'s power' : '') +
          (s.mode.slice(8, 9) === 'w' ? '  WARNING: anyone can write here' : ''));
      }
      L.push('', '  enter open   u up   i inspect   m new folder   d trash   n rename   c chmod   / go to');
    }
    if (st.prompt) L.push('', `  ${st.prompt.label} ${st.prompt.buf}_`);
    if (st.confirm) L.push('', `  Move ${sel() && sel().name} to the trash? y/n`);
    if (st.note) L.push('', '  ' + st.note);
    app.screen('File systems', L.slice(0, app.height - 2), 'changes need the admin keyboard + your password');
  };
  const change = (op, p, extra) => { st.note = `asking to ${op} ${p} - password in the OS prompt`; app.requestFsChange(op, p, extra); };
  for await (const ev of app.events()) {
    nav.see(ev);
    if (ev.cmd === 'hello') { app.requestApps(); app.requestSys('mounts'); app.requestLs(st.path); }
    else if (ev.cmd === 'launch') {
      if (ev.command === 'mounts') st.tab = 1;
      else if (ev.command === 'permissions') st.tab = 2;
      else if (ev.command === 'mkdir') { st.tab = 2; st.prompt = { kind: 'mkdir', label: 'new folder name:', buf: '' }; }
    } else if (ev.cmd === 'sys' && ev.kind === 'mounts') st.mounts = ev.data;
    else if (ev.cmd === 'sys' && ev.kind === 'stat') st.stat = ev.data;
    else if (ev.cmd === 'listing') { st.path = ev.path; st.entries = ev.entries; cur.sel = 0; inspect(); }
    else if (ev.cmd === 'result') { st.note = (ev.ok ? '' : 'NOT DONE: ') + ev.detail; if (ev.ok) { app.requestLs(st.path); app.requestSys('mounts'); } }
    else if (ev.cmd === 'key') {
      const k = ev.key;
      if (st.prompt) {
        if (k === 'enter') {
          const { kind, buf } = st.prompt; st.prompt = null;
          const e = sel();
          if (kind === 'goto' && buf) { st.tab = 2; app.requestLs(buf); }
          else if (kind === 'mkdir' && buf) change('mkdir', join(st.path, buf));
          else if (kind === 'rename' && e && buf) change('rename', join(st.path, e.name), { to: join(st.path, buf) });
          else if (kind === 'chmod' && e && buf) change('chmod', join(st.path, e.name), { mode: buf });
        } else if (k === 'escape') st.prompt = null;
        else if (k === 'backspace') st.prompt.buf = st.prompt.buf.slice(0, -1);
        else if (k.length === 1) st.prompt.buf += k;
      } else if (st.confirm) {
        st.confirm = false;
        if (k === 'y' && sel()) change('trash', join(st.path, sel().name));
      } else if (k === '1' || k === '2') st.tab = Number(k);
      else if (st.tab === 2 && cur.key(k, st.entries.length)) inspect();
      else if (k === 'enter' && sel() && sel().kind !== 'file') app.requestLs(join(st.path, sel().name));
      else if (k === 'u' || k === 'backspace') app.requestLs(path.posix.dirname(st.path.replace(/\/$/, '')) || '/');
      else if (k === '/') st.prompt = { kind: 'goto', label: 'go to path:', buf: '' };
      else if (k === 'i') inspect();
      else if (k === 'm') st.prompt = { kind: 'mkdir', label: 'new folder name:', buf: '' };
      else if (k === 'n' && sel()) st.prompt = { kind: 'rename', label: 'new name:', buf: sel().name };
      else if (k === 'c' && sel()) st.prompt = { kind: 'chmod', label: 'mode (octal, e.g. 644):', buf: '' };
      else if (k === 'd' && sel()) st.confirm = true;
      else if (k === 'q' || k === 'escape') nav.back();
    }
    if (ev.cmd !== 'pointer') render();
  }
})();

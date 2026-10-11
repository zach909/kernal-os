'use strict';
// Software sources & updates. Shows where every app, KOS itself and the runtimes
// underneath came from; keeps the list of places you get software; checks them
// (your password: it contacts the network) and installs newer versions (scanned,
// hash-checked, sealed - and held back if the new version wants MORE permissions).
const path = require('path');
const { App } = require(process.env.KOS_SDK_JS);
const K = require(path.join(path.dirname(process.env.KOS_SDK_JS), 'kit.js'));

const TABS = ['Where things come from', 'Sources', 'Updates'];
const day = (t) => (t ? new Date(t * 1000).toISOString().slice(0, 10) : '-');

(async () => {
  const app = new App();
  const nav = new K.Nav(app), cur = new K.Cursor();
  const st = { tab: 0, d: null, prompt: null, confirm: null, note: '' };
  const report = () => (st.d && st.d.last) || null;
  const todo = () => { const r = report(); return r ? [...r.updates.map((u) => ({ ...u, upd: true })), ...r.new.map((n) => ({ ...n, upd: false }))] : []; };
  const listLen = () => (st.tab === 1 ? (st.d ? st.d.sources.length : 0) : st.tab === 2 ? todo().length : 0);
  const render = () => {
    const d = st.d;
    const L = ['', '  ' + TABS.map((t, i) => (i === st.tab ? `[${i + 1} ${t}]` : ` ${i + 1} ${t} `)).join(' '), ''];
    if (!d) { L.push('  asking the OS...'); return app.screen('Updates', L, ''); }
    if (st.tab === 0) {
      L.push('  Apps');
      for (const a of d.apps) L.push(`    ${K.pad(a.name, 14)} ${K.pad(a.version, 7)} ${K.pad(a.source, 14)} ${K.fit(a.location || '-', 38)} ${day(a.updated)}${a.known ? '' : '  ?'}`);
      const k = d.core;
      L.push('  KOS itself', `    ${k.kind === 'git' ? `git ${k.branch}@${k.commit}${k.dirty ? ' (modified)' : ''}  ${k.origin}` : k.origin}`, `    updates: ${k.update}`);
      L.push('  Underneath (updated by your operating system, not by KOS)');
      for (const r of d.runtimes) L.push(`    ${K.pad(r.name, 16)} ${K.pad(r.version, 20)} ${K.fit(r.origin, 36)}`);
    } else if (st.tab === 1) {
      L.push('  Places you get software from (checking one contacts it, and asks your password)');
      cur.clamp(d.sources.length);
      d.sources.forEach((s, i) => L.push((i === cur.sel ? '  > ' : '    ') + K.pad(s.name, 14) + K.pad(s.kind, 8) + s.location));
      if (!d.sources.length) L.push('    none yet - press a');
      L.push('', '  kinds: folder (a directory of .kapp files)   https (a site with kapps.json)   github (OWNER/REPO releases)');
    } else {
      const r = report();
      L.push(r ? `  Last check ${new Date(r.t * 1000).toTimeString().slice(0, 8)}` : '  Not checked yet - press c (asks your password, contacts your sources)');
      const items = todo();
      cur.clamp(items.length);
      items.forEach((u, i) => {
        const hold = u.adds_permissions && u.adds_permissions.length ? `  HOLD: wants new permissions ${u.adds_permissions.join(',')}` : '';
        L.push((i === cur.sel ? '  > ' : '    ') + (u.upd ? `update ${K.pad(u.name, 14)} ${u.installed} -> ${u.version}` : `new    ${K.pad(u.name, 14)} ${u.version}`) + `  from ${u.source}${hold}`);
      });
      if (r && !items.length) L.push('    everything from your sources is up to date');
      for (const e of (r && r.errors) || []) L.push('    ! ' + K.fit(e, 90));
      const c = r && r.core;
      if (c) L.push('', `  KOS itself: ${c.error ? 'cannot check - ' + K.fit(c.error, 60) : c.behind ? `${c.behind} new commit(s) available (u to update)` : 'up to date'}`,
        ...(c.subjects || []).slice(0, 3).map((s) => '    - ' + K.fit(s, 80)));
      L.push('', '  c check   i install selected   I install all   p install allowing new permissions   u update KOS');
    }
    if (st.prompt) L.push('', `  ${st.prompt.label} ${st.prompt.buf}_`);
    if (st.confirm) L.push('', `  ${st.confirm.text} y/n`);
    if (st.note) L.push('', '  ' + st.note);
    app.screen('Updates', L.slice(0, app.height - 2), '1-3 tabs | a add source | x remove | q back');
  };
  const refresh = () => app.requestUpdates('provenance');
  for await (const ev of app.events()) {
    nav.see(ev);
    if (ev.cmd === 'hello') { app.requestApps(); refresh(); }
    else if (ev.cmd === 'updates') {
      if (ev.op === 'provenance') st.d = ev.data;
      else if (ev.op === 'check') { st.note = `checked: ${ev.data.updates.length} update(s), ${ev.data.new.length} new`; refresh(); }
    } else if (ev.cmd === 'result') { st.note = (ev.ok ? '' : 'NOT DONE: ') + ev.detail; refresh(); }
    else if (ev.cmd === 'text') { st.note = ev.lines.join(' | '); refresh(); }
    else if (ev.cmd === 'key') {
      const k = ev.key, items = todo(), pick = items[cur.sel];
      if (st.prompt) {
        if (k === 'enter') {
          const parts = st.prompt.buf.trim().split(/\s+/); st.prompt = null;
          if (parts.length === 3) app.requestUpdates('source_add', { name: parts[0], kind: parts[1], location: parts[2] });
          else st.note = 'type: NAME KIND LOCATION  (e.g.  work folder /srv/kapps)';
        } else if (k === 'escape') st.prompt = null;
        else if (k === 'backspace') st.prompt.buf = st.prompt.buf.slice(0, -1);
        else if (k.length === 1) st.prompt.buf += k;
      } else if (st.confirm) {
        const c = st.confirm; st.confirm = null;
        if (k === 'y') c.run();
      } else if ('123'.includes(k) && k) { st.tab = Number(k) - 1; cur.sel = 0; }
      else if (cur.key(k, listLen())) { /* moved */ }
      else if (k === 'a' && st.tab === 1) st.prompt = { label: 'name kind location:', buf: '' };
      else if (k === 'x' && st.tab === 1 && st.d.sources[cur.sel]) {
        const s = st.d.sources[cur.sel];
        st.confirm = { text: `Remove source ${s.name}?`, run: () => app.requestUpdates('source_remove', { name: s.name }) };
      } else if (k === 'c') { st.tab = 2; st.note = 'checking your sources - type your password in the OS prompt'; app.requestUpdates('check'); }
      else if (k === 'i' && pick) { st.note = `installing ${pick.name}...`; app.requestUpdates('install', { name: pick.name }); }
      else if (k === 'I') { st.note = 'installing every update that needs no new permissions...'; app.requestUpdates('install_all'); }
      else if (k === 'p' && pick) {
        st.confirm = { text: `${pick.name} ${pick.version} asks for more permissions than the version you have. Allow?`,
          run: () => app.requestUpdates('install', { name: pick.name, permissions: true }) };
      } else if (k === 'u') { st.note = 'updating KOS itself...'; app.requestUpdates('core'); }
      else if (k === 'q' || k === 'escape') nav.back();
    }
    if (ev.cmd !== 'pointer') render();
  }
})();

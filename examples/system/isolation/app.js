'use strict';
// Protection & isolation: how each app is confined, how hardened the kernel is, and
// who may do what. All facts come from the OS; nothing here can change them.
const path = require('path');
const { App } = require(process.env.KOS_SDK_JS);
const K = require(path.join(path.dirname(process.env.KOS_SDK_JS), 'kit.js'));

const GOOD = { 'kernel/yama/ptrace_scope': (v) => +v >= 1, 'kernel/kptr_restrict': (v) => +v >= 1,
  'kernel/dmesg_restrict': (v) => v === '1', 'kernel/unprivileged_bpf_disabled': (v) => +v >= 1,
  'kernel/kexec_load_disabled': (v) => v === '1', 'kernel/sysrq': (v) => v === '0',
  'fs/protected_symlinks': (v) => v === '1', 'fs/protected_hardlinks': (v) => v === '1',
  'fs/suid_dumpable': (v) => v === '0', 'vm/unprivileged_userfaultfd': (v) => v === '0' };
const WHY = { 'kernel/yama/ptrace_scope': 'programs cannot read each other\'s memory', 'kernel/kptr_restrict': 'kernel addresses hidden',
  'kernel/dmesg_restrict': 'kernel log needs privilege', 'kernel/unprivileged_bpf_disabled': 'no user-loaded kernel code',
  'kernel/kexec_load_disabled': 'cannot swap in another kernel', 'kernel/sysrq': 'magic keys off',
  'fs/protected_symlinks': 'symlink tricks in shared dirs blocked', 'fs/protected_hardlinks': 'hard-link tricks blocked',
  'fs/suid_dumpable': 'privileged crashes not dumped', 'vm/unprivileged_userfaultfd': 'a kernel-race helper is off' };

(async () => {
  const app = new App();
  const nav = new K.Nav(app), cur = new K.Cursor();
  const st = { d: null, tab: 0, n: 0 };
  const render = () => {
    const d = st.d;
    const L = ['', '  ' + ['1 Apps', '2 Kernel hardening', '3 Access'].map((t, i) => (i === st.tab ? `[${t}]` : ` ${t} `)).join(' '), ''];
    if (!d) { L.push('  asking the OS...'); return app.screen('Protection', L, ''); }
    if (st.tab === 0) {
      if (!d.apps.length) L.push('  no KOS apps are running right now - each runs in its own cage:');
      cur.clamp(d.apps.length);
      for (const a of d.apps) {
        L.push(`  ${K.pad(a.name, 14)} pid ${a.pid}  uid ${a.uid}${a.uid === 65534 || a.uid > 0 ? '' : '  (ROOT!)'}  own memory ${K.kb(a.own_memory_kb)}`);
        L.push(`      no_new_privs ${a.no_new_privs ? 'yes' : 'NO'}   seccomp ${a.seccomp}   capabilities ${a.cap_effective}`);
        L.push(`      separate: ${a.separate_namespaces.join(' ') || 'none'}   shared: ${a.shared_namespaces.join(' ') || 'none'}`);
      }
      L.push('', '  Each app is its own process in its own memory space, cannot gain privileges, sees', '  an empty network (unless allowed), and can only read what the sandbox lists.');
    } else if (st.tab === 1) {
      for (const [k, v] of Object.entries(d.hardening)) {
        const ok = GOOD[k] ? GOOD[k](v) : true;
        L.push(`  ${ok ? 'ok  ' : 'WEAK'} ${K.pad(k, 34)} = ${K.pad(v || '?', 4)} ${WHY[k] || ''}`);
      }
    } else {
      const a = d.auth;
      L.push(`  You are ${a.root ? 'root (KOS refuses to be run this way on a real system)' : 'an ordinary user'} (uid ${a.uid})`);
      L.push(`  Password: ${a.failed_attempts} failed attempt(s) on record${a.wait_s ? `, locked out for ${a.wait_s}s` : ''}`);
      L.push(`  ${a.admin_keyboard}`);
      L.push('', '  Two access levels: ordinary actions need your password; changing files needs the', '  administrator keyboard too. Apps allowed to run:');
      L.push('    ' + (a.permitted_apps.join(', ') || '(none)'));
    }
    app.screen('Protection', L.slice(0, app.height - 2), '1-3 tabs | r refresh | q back');
  };
  for await (const ev of app.events()) {
    nav.see(ev);
    if (ev.cmd === 'hello') { app.requestApps(); app.requestSys('isolation'); }
    else if (ev.cmd === 'tick') { if (++st.n % 3 === 0) app.requestSys('isolation'); continue; }
    else if (ev.cmd === 'sys' && ev.kind === 'isolation') st.d = ev.data;
    else if (ev.cmd === 'key') {
      const k = ev.key;
      if ('123'.includes(k) && k) st.tab = Number(k) - 1;
      else if (k === 'r') app.requestSys('isolation');
      else if (k === 'q' || k === 'escape') nav.back();
    }
    if (ev.cmd !== 'pointer') render();
  }
})();

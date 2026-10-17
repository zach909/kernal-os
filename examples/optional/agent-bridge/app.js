'use strict';
// Agent bridge. An outside AI agent - Claude Code, a script, any program you run yourself - cannot be put inside the OS, and should not be
// trusted with it. This app is the mailbox between the two. The agent writes a plan as a JSON file into this app's inbox folder:
//     {"agent": "claude-code", "title": "Check the machine", "steps": [{"action": "open", "app": "resources"}, {"action": "sys", "kind": "memory"}]}
// (or runs `kos agent propose plan.json`). The bridge checks it is an allowed shape - at most eight steps, only launching and looking - and
// proposes it to the OS like any assistant. The OS shows the plan and asks for YOUR password (never remembered, so a sudo window cannot approve it);
// only then does each step run, as this app, with only the scopes in this manifest. The answer is written back to the outbox folder for the agent.
// The agent itself gets nothing: not the password, not the screen, not a way to act on its own.
const fs = require('fs');
const path = require('path');
const { App, Canvas } = require(process.env.KOS_SDK_JS);
const G = require(path.join(path.dirname(process.env.KOS_SDK_JS), 'gfx.js'));
const { plan } = require('./plan.js');

(async () => {
  const app = new App();
  const root = app.dataDir();
  const dirs = root ? { inbox: path.join(root, 'inbox'), outbox: path.join(root, 'outbox') } : null;
  if (dirs) for (const d of Object.values(dirs)) fs.mkdirSync(d, { recursive: true });
  const st = { waiting: null, log: [] };
  const say = (line) => { st.log.unshift(line); st.log.length = Math.min(st.log.length, 8); };
  const answer = (name, doc) => {
    if (!dirs) return;
    try { fs.writeFileSync(path.join(dirs.outbox, name.replace(/\.json$/, '') + '.result.json'), JSON.stringify({ ...doc, at: new Date().toISOString() }, null, 2)); } catch (e) { /* the outbox is gone: nothing to tell */ }
  };
  const draw = () => {
    const c = new Canvas(), u = app.scale;
    G.stext(c, app, 16 * u, 10 * u, 'Agent bridge', '#ffffff', 11 * u, 1);
    G.stext(c, app, 16 * u, 26 * u, 'Outside AI agents propose plans here. Nothing runs unless you type your password.', '#9fb2c8', 6 * u + 1);
    G.stext(c, app, 16 * u, 42 * u, dirs ? `Inbox: ${dirs.inbox}` : 'No data folder: nothing can arrive.', '#aab4c4', 5 * u + 1);
    let y = 62 * u;
    G.stext(c, app, 16 * u, y, st.waiting ? `Waiting for you: ${st.waiting}` : 'No plan waiting.', st.waiting ? '#ffd166' : '#9fb2c8', 7 * u + 1, 1); y += 18 * u;
    for (const line of st.log) { G.stext(c, app, 16 * u, y, line, '#e3ebf6', 6 * u + 1); y += 11 * u; }
    app.present(c);
  };
  const drop = (file) => { try { fs.rmSync(file, { force: true }); } catch (e) { /* not ours to remove */ } };
  const next = () => {
    if (st.waiting || !dirs) return;
    let names = [];
    try { names = fs.readdirSync(dirs.inbox).filter((n) => /^[A-Za-z0-9._-]{1,80}\.json$/.test(n)).sort(); } catch (e) { return; }
    for (const name of names) {
      const file = path.join(dirs.inbox, name);
      let doc;
      try {
        if (fs.statSync(file).size > 20000) throw new Error('too big');
        doc = JSON.parse(fs.readFileSync(file, 'utf8'));
      } catch (e) { say(`${name}: not readable JSON; discarded`); answer(name, { ok: false, detail: 'not readable JSON (or over 20 KB)' }); drop(file); continue; }
      const got = plan(doc);
      if (!got.ok) { say(`${name}: refused (${got.why})`); answer(name, { ok: false, detail: got.why }); drop(file); continue; }
      const who = typeof doc.agent === 'string' ? doc.agent.replace(/[^A-Za-z0-9 ._-]/g, '').slice(0, 30) : 'an agent';
      st.waiting = { name, title: got.plan.title, who };
      st.waiting.toString = () => `${who}: ${got.plan.title}`;
      try { fs.rmSync(file, { force: true }); } catch (e) { say(`${name}: could not be taken from the inbox`); st.waiting = null; continue; }
      app.requestPropose(`${who}: ${got.plan.title}`.slice(0, 80), got.plan.steps);
      break;
    }
  };
  for await (const ev of app.events()) {
    if (ev.cmd === 'tick' || ev.cmd === 'hello') next();
    else if (ev.cmd === 'result' && ev.action === 'propose' && st.waiting) {
      const w = st.waiting; st.waiting = null;
      say(`${w.who}: ${w.title} - ${ev.ok ? 'you approved it' : 'not run'}`);
      answer(w.name, { ok: !!ev.ok, detail: ev.detail, agent: w.who, title: w.title });
      next();
    } else if (ev.cmd !== 'hello') continue;
    draw();
  }
})();

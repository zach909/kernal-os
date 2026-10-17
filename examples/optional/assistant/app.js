'use strict';
// An assistant that must ask permission.
//
// An AI assistant is an ordinary KOS app with the `assist` permission. It has no network unless you gave it some, no files, no
// password, and no way to act on its own: all it can do is PROPOSE a plan - up to eight steps, only launching and looking actions - and
// the OS shows you the plan and asks for your password. If you do not type it, nothing happens. If you do, each step runs *as the
// assistant*, with only the scopes the assistant holds (this one: system:apps) and with whatever password that step needs by itself.
// Nothing an assistant proposes can change a file, send anything out, signal a process, widen a permission or open a sudo window.
//
// This one is a RULE-BASED STAND-IN: it understands "open files", "show processes", "check updates"... A real model plugs in the same
// way - an assistant app that you let reach its model (the network permission is asked for separately) and that turns what you type
// into the same kind of plan.
const path = require('path');
const { App, Canvas } = require(process.env.KOS_SDK_JS);
const G = require(path.join(path.dirname(process.env.KOS_SDK_JS), 'gfx.js'));

const ALIASES = { processes: 'processes', process: 'processes', memory: 'memory', network: 'network', devices: 'devices', updates: 'updates',
  files: 'files', terminal: 'terminal', editor: 'editor', settings: 'settings', security: 'security', backup: 'backup', health: 'health',
  disk: 'filesystem', resources: 'resources', browser: 'browser' };

function plan(text) {
  const t = text.toLowerCase();
  const steps = [];
  for (const w of t.split(/[^a-z-]+/)) if (ALIASES[w] && !steps.some((s) => s.app === ALIASES[w])) steps.push({ action: 'open', app: ALIASES[w], mode: 'graphical' });
  if (/what.*(slow|using|eating)|why.*(slow|hot)/.test(t) && !steps.some((s) => s.app === 'resources')) steps.push({ action: 'open', app: 'resources', mode: 'graphical' });
  return steps.slice(0, 8);
}

(async () => {
  const app = new App();
  const st = { text: '', steps: [], note: 'Tell me what you want to look at, then press Enter. I can only propose; you approve with your password.', last: '' };
  const draw = () => {
    const c = new Canvas(), u = app.scale, W = app.width, H = app.height;
    G.stext(c, app, 12 * u, 8 * u, 'Assistant', '#ffffff', 11 * u, 1);
    G.stext(c, app, 12 * u, 24 * u, 'rule-based stand-in - it only proposes, you approve', '#f0b44a', 6 * u, 0);
    G.roundRect(c, 10 * u, 38 * u, W - 20 * u, 20 * u, 8 * u, '#14171c');
    c.hit(10 * u, 38 * u, W - 20 * u, 20 * u, 'What should I do?');
    G.stext(c, app, 18 * u, 42 * u, st.text ? st.text + (Math.floor(Date.now() / 500) % 2 ? '|' : '') : 'e.g. open files and processes', st.text ? '#ffffff' : '#7f8da3', 8 * u, 0, null);
    let y = 66 * u;
    G.stext(c, app, 12 * u, y, st.steps.length ? 'My plan (you will be asked before anything runs):' : st.note, '#cfe3ff', 6 * u, 0);
    y += 12 * u;
    st.steps.forEach((s, i) => { G.stext(c, app, 18 * u, y, `${i + 1}. open ${s.app}`, '#ffffff', 7 * u, 1, null); y += 11 * u; });
    if (st.last) G.stext(c, app, 12 * u, H - 14 * u, st.last, '#9fb2c8', 6 * u, 0);
    app.present(c);
  };
  for await (const ev of app.events()) {
    if (ev.cmd === 'key') {
      if (ev.key === 'enter') {
        if (st.steps.length) { app.requestPropose(`do what you asked: ${st.text}`.slice(0, 80), st.steps); st.steps = []; st.text = ''; }
        else { st.steps = plan(st.text); st.note = st.steps.length ? '' : "I did not understand that. Try: open files, show processes, check updates."; }
      } else if (ev.key === 'backspace') { st.text = st.text.slice(0, -1); st.steps = []; }
      else if (ev.key === 'escape') { st.text = ''; st.steps = []; }
      else if (ev.key.length === 1) { st.text = (st.text + ev.key).slice(0, 80); st.steps = []; }
    } else if (ev.cmd === 'result' && ev.action === 'propose') st.last = ev.detail;
    else if (ev.cmd !== 'hello' && ev.cmd !== 'focus' && ev.cmd !== 'look' && ev.cmd !== 'tick') continue;
    draw();
  }
})();

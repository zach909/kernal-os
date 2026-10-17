'use strict';
// What an agent may propose. The same shape the OS accepts for an assistant plan (kos/protocol.py): at most eight steps, only launching and
// looking actions. Anything else is refused HERE, before it reaches the OS (which would drop this app for sending a malformed request).
const APP = /^[a-z][a-z0-9-]{0,31}$/;
const INSTANCE = /^[a-z][a-z0-9-]{0,31}-[0-9a-f]{6}$/;
const SYS_KINDS = new Set(['devices', 'health', 'isolation', 'memory', 'mounts', 'network', 'processes', 'resources']);
const text = (v, n) => typeof v === 'string' && v.length > 0 && v.length <= n && !/[\u0000-\u001f]/.test(v);

function step(st) {
  if (!st || typeof st !== 'object' || Array.isArray(st)) return null;
  switch (st.action) {
    case 'apps': case 'info': case 'netcheck': return { action: st.action };
    case 'open': {
      if (typeof st.app !== 'string' || !APP.test(st.app)) return null;
      const out = { action: 'open', app: st.app, mode: 'graphical' };
      if (st.mode !== undefined) { if (!['tui', 'graphical'].includes(st.mode)) return null; out.mode = st.mode; }
      return out;
    }
    case 'focus': case 'close': return typeof st.id === 'string' && INSTANCE.test(st.id) ? { action: st.action, id: st.id } : null;
    case 'sys': return typeof st.kind === 'string' && SYS_KINDS.has(st.kind) ? { action: 'sys', kind: st.kind } : null;
    default: return null;
  }
}

// -> { ok: true, plan: {title, steps} } | { ok: false, why }
function plan(doc) {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return { ok: false, why: 'a plan is a JSON object' };
  if (!text(doc.title, 80)) return { ok: false, why: 'title: 1 to 80 characters' };
  if (!Array.isArray(doc.steps) || doc.steps.length < 1 || doc.steps.length > 8) return { ok: false, why: 'steps: 1 to 8' };
  const steps = [];
  for (const [i, st] of doc.steps.entries()) {
    const s = step(st);
    if (!s) return { ok: false, why: `step ${i + 1} is not an allowed launching or looking action` };
    steps.push(s);
  }
  return { ok: true, plan: { title: doc.title, steps } };
}

module.exports = { plan };

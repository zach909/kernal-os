'use strict';
// Small helpers the built-in apps share: formatting, bars, sparklines, tables,
// "back to the taskbar". Pure functions plus one tiny class; no dependencies.

const HOME = 'taskbar';

const bytes = (n) => {
  const u = ['B', 'K', 'M', 'G', 'T', 'P'];
  let i = 0;
  n = Number(n) || 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i === 0 ? String(Math.round(n)) : n.toFixed(n >= 100 ? 0 : 1)) + u[i];
};
const kb = (n) => bytes((Number(n) || 0) * 1024);
const pct = (f) => `${Math.round(Math.max(0, Math.min(1, f || 0)) * 100)}%`;
const dur = (s) => {
  s = Math.max(0, Math.floor(s));
  const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
  return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : m ? `${m}m ${s % 60}s` : `${s}s`;
};
const fit = (s, n) => { s = String(s ?? ''); return s.length > n ? s.slice(0, Math.max(0, n - 1)) + '~' : s; };
const pad = (s, n) => fit(s, n).padEnd(n);
const rpad = (s, n) => fit(s, n).padStart(n);

/** [#####-----] 0..1 */
const bar = (f, width = 20) => {
  const k = Math.round(Math.max(0, Math.min(1, f || 0)) * width);
  return '[' + '#'.repeat(k) + '-'.repeat(width - k) + ']';
};

/** A sparkline of the last N samples, scaled to the max seen. */
const spark = (series, width = 40) => {
  const chars = ' .:-=+*#%@';
  const s = series.slice(-width);
  const hi = Math.max(1e-9, ...s);
  return s.map((v) => chars[Math.min(chars.length - 1, Math.round((v / hi) * (chars.length - 1)))]).join('');
};

/** Keep the last `n` values. */
class History {
  constructor(n = 120) { this.n = n; this.v = []; }
  push(x) { this.v.push(x); if (this.v.length > this.n) this.v.shift(); }
}

/** Keeps the open-app list from `apps` events so any app can go back to the taskbar. */
class Nav {
  constructor(app) { this.app = app; this.open = []; }
  see(ev) { if (ev.cmd === 'apps') this.open = ev.open || []; }
  back() {
    const t = this.open.find((i) => i.name === HOME && i.status === 'running');
    if (t) this.app.requestFocus(t.id);
  }
}

/** Selection list helper: moves with up/down and returns the visible window. */
class Cursor {
  constructor() { this.sel = 0; }
  clamp(n) { this.sel = n ? Math.max(0, Math.min(this.sel, n - 1)) : 0; }
  key(k, n) {
    if (!n) return false;
    if (k === 'up') this.sel = (this.sel - 1 + n) % n;
    else if (k === 'down') this.sel = (this.sel + 1) % n;
    else if (k === 'pageup') this.sel = Math.max(0, this.sel - 10);
    else if (k === 'pagedown') this.sel = Math.min(n - 1, this.sel + 10);
    else if (k === 'home') this.sel = 0;
    else if (k === 'end') this.sel = n - 1;
    else return false;
    return true;
  }
  window(n, room) {
    room = Math.max(1, room);
    const first = n > room ? Math.max(0, Math.min(this.sel - Math.floor(room / 2), n - room)) : 0;
    return [first, Math.min(n, first + room)];
  }
}

/** Per-second rate of a counter that grows over time. */
class Rate {
  constructor() { this.last = new Map(); }
  of(key, value, t) {
    const prev = this.last.get(key);
    this.last.set(key, [value, t]);
    if (!prev || t <= prev[1]) return 0;
    return Math.max(0, (value - prev[0]) / (t - prev[1]));
  }
}

module.exports = { HOME, bytes, kb, pct, dur, fit, pad, rpad, bar, spark, History, Nav, Cursor, Rate };

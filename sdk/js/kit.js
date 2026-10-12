'use strict';
// Small helpers the built-in apps share: formatting, bars, sparklines, tables,
// "back to the taskbar". Pure functions plus one tiny class; no dependencies.

const HOME = 'taskbar';
// The apps that make up the interface itself: they are not offered as things to launch.
const SHELL = new Set(['wallpaper', 'pins', 'search', 'sidebar', 'launcher', 'widgets', 'widget-clock', 'widget-calendar', 'widget-network', 'widget-system', 'menubar', 'dock', 'effects', 'cursor', 'taskbar']);

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

/** Rank search items against a query. Items: {name, words: [..]} (name weighs most). */
function rank(items, query, limit = 12) {
  const q = query.trim().toLowerCase();
  if (!q) return [];
  const terms = q.split(/\s+/);
  const scored = [];
  for (const it of items) {
    let total = 0;
    for (const t of terms) {
      const name = it.name.toLowerCase(), ws = name.split(/[^a-z0-9]+/);
      let best = 0;
      if (name === t) best = 100;
      else if (name.startsWith(t)) best = 80;
      else if (ws.some((w) => w.startsWith(t))) best = 60;
      else if (name.includes(t)) best = 40;
      else {
        for (const w of it.words || []) {
          const lw = w.toLowerCase();
          if (lw.startsWith(t)) best = Math.max(best, 30);
          else if (lw.split(/[^a-z0-9]+/).some((x) => x.startsWith(t))) best = Math.max(best, 25);
          else if (lw.includes(t)) best = Math.max(best, 15);
        }
        if (!best) {                                  // a subsequence ("prc" finds "processes")
          let i = 0;
          for (const ch of name) if (ch === t[i]) i++;
          if (i === t.length && t.length >= 2) best = 8;
        }
      }
      if (!best) { total = 0; break; }
      total += best;
    }
    if (total) scored.push({ ...it, score: total + (it.boost || 0) });
  }
  return scored.sort((a, b) => b.score - a.score || a.name.localeCompare(b.name)).slice(0, limit);
}

/** Guess what a typed pin is: an http(s) address, a path (a trailing / means a folder), or an app name. */
function parseLink(text, apps = []) {
  const t = String(text || '').trim();
  if (!t) return null;
  if (/^https?:\/\/\S{3,}$/i.test(t)) return { kind: 'url', target: t };
  if (/^www\.\S+\.\S+$/i.test(t)) return { kind: 'url', target: `https://${t}` };
  if (t.startsWith('/')) return { kind: t.endsWith('/') && t.length > 1 ? 'folder' : (/\.[A-Za-z0-9]{1,6}$/.test(t) ? 'file' : 'folder'), target: t };
  if (apps.some((a) => a.name === t.toLowerCase())) return { kind: 'app', target: t.toLowerCase() };
  return null;
}
/** The app whose icon stands for a kind of link. */
const LINK_ICON = { app: null, file: 'editor', folder: 'files', url: 'browser' };

module.exports = { parseLink, LINK_ICON, rank, HOME, SHELL, bytes, kb, pct, dur, fit, pad, rpad, bar, spark, History, Nav, Cursor, Rate };

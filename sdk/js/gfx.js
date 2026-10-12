'use strict';
// Drawing by code. Apps send flat shapes; the OS adds glass, blur, shadow and bevel
// around them. Everything here turns into rect/line/text operations - there are no
// image files anywhere in KOS.

const hex2 = (n) => Math.max(0, Math.min(255, Math.round(n))).toString(16).padStart(2, '0');
const rgb = (c) => [parseInt(c.slice(1, 3), 16), parseInt(c.slice(3, 5), 16), parseInt(c.slice(5, 7), 16)];
const color = (r, g, b) => `#${hex2(r)}${hex2(g)}${hex2(b)}`;
const mix = (a, b, t) => { const x = rgb(a), y = rgb(b); return color(x[0] + (y[0] - x[0]) * t, x[1] + (y[1] - x[1]) * t, x[2] + (y[2] - x[2]) * t); };
const lighten = (c, t) => mix(c, '#ffffff', t);
const darken = (c, t) => mix(c, '#000000', t);

/** A colour for a name, so every app gets its own stable one (hue from the name, fixed saturation/lightness). */
const hue = (name) => {
  let h = 0;
  for (const ch of name) h = (h * 31 + ch.charCodeAt(0)) % 360;
  const c = 0.62 * (1 - Math.abs(2 * 0.5 - 1)), x = c * (1 - Math.abs((h / 60) % 2 - 1)), m = 0.5 - c / 2;
  const [r, g, b] = h < 60 ? [c, x, 0] : h < 120 ? [x, c, 0] : h < 180 ? [0, c, x] : h < 240 ? [0, x, c] : h < 300 ? [x, 0, c] : [c, 0, x];
  return color((r + m) * 255, (g + m) * 255, (b + m) * 255);
};

/** Vertical gradient as horizontal slices (at most ~160 operations). */
function gradV(c, x, y, w, h, top, bottom) {
  const step = Math.max(1, Math.ceil(h / 160));
  for (let i = 0; i < h; i += step) c.rect(x, y + i, w, Math.min(step, h - i), mix(top, bottom, h <= 1 ? 0 : i / (h - 1)));
}

/** Inset of a rounded corner at row i (0 = outermost). */
const inset = (r, i) => (i >= r ? 0 : r - Math.round(Math.sqrt(Math.max(0, r * r - (r - i - 0.5) ** 2))));

function roundRect(c, x, y, w, h, r, col) {
  r = Math.max(0, Math.min(r, Math.floor(Math.min(w, h) / 2)));
  for (let i = 0; i < r; i++) {                                    // top and bottom caps, a row at a time
    const d = inset(r, i);
    c.rect(x + d, y + i, w - 2 * d, 1, col);
    c.rect(x + d, y + h - 1 - i, w - 2 * d, 1, col);
  }
  c.rect(x, y + r, w, h - 2 * r, col);                              // the straight middle in one operation
}

function roundGradient(c, x, y, w, h, r, top, bottom) {
  r = Math.min(r, Math.floor(Math.min(w, h) / 2));
  const step = Math.max(1, Math.ceil(h / 36));
  for (let i = 0; i < h; i += step) {
    const n = Math.min(i, h - 1 - i), d = inset(r, n);
    c.rect(x + d, y + i, w - 2 * d, Math.min(step, h - i), mix(top, bottom, h <= 1 ? 0 : i / (h - 1)));
  }
}

function circle(c, cx, cy, r, col) {
  for (let dy = -r; dy <= r; dy++) {
    const half = Math.round(Math.sqrt(Math.max(0, r * r - dy * dy)));
    c.rect(cx - half, cy + dy, 2 * half + 1, 1, col);
  }
}

function ring(c, cx, cy, r, col, segments = 72) {
  for (let i = 0; i < segments; i++) {
    const a0 = (i / segments) * 2 * Math.PI, a1 = ((i + 1) / segments) * 2 * Math.PI;
    c.line(Math.round(cx + r * Math.cos(a0)), Math.round(cy + r * Math.sin(a0)), Math.round(cx + r * Math.cos(a1)), Math.round(cy + r * Math.sin(a1)), col);
  }
}

/** Text with a drop shadow (keeps it readable on glass). */
function text(c, x, y, s, col, scale = 1, shadow = '#000000') {
  c.text(x + scale, y + scale, s, shadow, scale);
  c.text(x, y, s, col, scale);
}
/** Smooth text with a soft shadow (face 0 sans, 1 bold, 2 mono). `app` supplies the font's advances. */
function stext(c, app, x, y, s, col, px, face = 0, shadow = '#000000') {
  if (shadow) c.stext(x + 1, y + 1, s, shadow, px, face);
  c.stext(x, y, s, col, px, face);
}
function stextCentered(c, app, cx, y, s, col, px, face = 0, shadow = '#000000') {
  stext(c, app, Math.round(cx - app.textWidth(s, px, face) / 2), y, s, col, px, face, shadow);
}
const textWidth = (s, scale = 1) => String(s).length * 6 * scale;
function textCentered(c, cx, y, s, col, scale = 1) { text(c, Math.round(cx - textWidth(s, scale) / 2), y, s, col, scale); }

/** A raised, glossy 3D button. `state`: 'normal' | 'hot' | 'down'. */
function button(c, x, y, w, h, label, { scale = 1, base = ACCENT, state = 'normal', text: tcol = '#ffffff' } = {}) {
  const r = Math.max(2, Math.round(h / 4));
  const b = state === 'hot' ? lighten(base, 0.18) : state === 'down' ? darken(base, 0.2) : base;
  roundRect(c, x + 1, y + 2, w, h, r, darken(base, 0.7));                      // shadow
  roundGradient(c, x, state === 'down' ? y + 1 : y, w, h, r, lighten(b, 0.25), darken(b, 0.25));
  roundGradient(c, x + 2, (state === 'down' ? y + 1 : y) + 1, w - 4, Math.max(2, Math.floor(h / 2)), Math.max(1, r - 2), lighten(b, 0.5), lighten(b, 0.15));   // gloss
  if (label) textCentered(c, x + w / 2, y + Math.round((h - 7 * scale) / 2) + (state === 'down' ? 1 : 0), label, tcol, scale);
}

/** An app icon, drawn by code: a glossy tile in the app's own colour with a pictogram. */
function icon(c, x, y, size, name, { hot = false } = {}) {
  const base = hue(name), r = Math.round(size / 4.5), deep = look === '3d';
  if (deep) {                                                                                       // 3D: a thick, glossy tile with a long shadow
    roundRect(c, x + 3, y + 8, size, size, r, darken(base, 0.82));
    roundRect(c, x + 1, y + 5, size, size, r, darken(base, 0.6));
    roundGradient(c, x, y, size, size, r, lighten(base, hot ? 0.55 : 0.4), darken(base, 0.4));
    roundGradient(c, x + 2, y + 2, size - 4, Math.floor(size / 2.2), Math.max(2, r - 2), lighten(base, 0.75), lighten(base, 0.25));
  } else {                                                                                          // normal: a clean tile
    roundRect(c, x + 1, y + 3, size, size, r, darken(base, 0.8));
    roundGradient(c, x, y, size, size, r, lighten(base, hot ? 0.35 : 0.22), darken(base, 0.18));
  }
  const g = lighten(base, 0.9), d = darken(base, 0.6), s = size, cx = x + s / 2, cy = y + s / 2, u = s / 10;
  const R = (a, b, w, h, col) => c.rect(Math.round(x + a * u), Math.round(y + b * u), Math.max(1, Math.round(w * u)), Math.max(1, Math.round(h * u)), col);
  const P = {
    files: () => { R(2, 3.5, 6, 4.5, g); R(2, 2.5, 2.5, 1.5, g); R(2, 5, 6, 0.4, d); },
    editor: () => { R(2.6, 2, 4.8, 6, g); R(3.4, 3.4, 3.2, 0.5, d); R(3.4, 4.8, 3.2, 0.5, d); R(3.4, 6.2, 2, 0.5, d); },
    terminal: () => { R(1.8, 2.4, 6.4, 5.2, d); c.line(Math.round(x + 2.8 * u), Math.round(y + 3.6 * u), Math.round(x + 4.2 * u), Math.round(y + 4.8 * u), g); c.line(Math.round(x + 4.2 * u), Math.round(y + 4.8 * u), Math.round(x + 2.8 * u), Math.round(y + 6 * u), g); R(5, 6, 2.4, 0.6, g); },
    settings: () => { circle(c, Math.round(cx), Math.round(cy), Math.round(2.6 * u), g); circle(c, Math.round(cx), Math.round(cy), Math.round(1.1 * u), d); for (let a = 0; a < 8; a++) { const t = a * Math.PI / 4; R(5 + 3.1 * Math.cos(t) - 0.5, 5 + 3.1 * Math.sin(t) - 0.5, 1, 1, g); } },
    network: () => { for (let i = 0; i < 4; i++) R(2.2 + i * 1.6, 7.6 - i * 1.5 - 0.6, 1.1, 1.2 + i * 1.5, g); },
    processes: () => { for (let i = 0; i < 4; i++) { R(2.2, 2.4 + i * 1.6, 5.6 - (i % 2) * 1.6, 0.9, g); } },
    memory: () => { R(2, 3.6, 6, 2.8, g); for (let i = 0; i < 5; i++) R(2.4 + i * 1.1, 4.1, 0.6, 1.8, d); R(2.4, 6.4, 5.2, 0.5, d); },
    filesystem: () => { R(2.2, 2.6, 5.6, 1.7, g); R(2.2, 4.6, 5.6, 1.7, g); R(2.2, 6.6, 5.6, 1.4, g); },
    devices: () => { R(2.4, 2.4, 5.2, 3.6, g); R(3, 3, 4, 2.4, d); R(4, 6.4, 2, 0.8, g); R(3.2, 7.4, 3.6, 0.6, g); },
    isolation: () => { R(2.6, 2.4, 4.8, 4, g); R(3.4, 6.4, 3.2, 1.3, g); R(4.5, 3.6, 1, 1.6, d); },
    health: () => { R(4.2, 2.2, 1.6, 5.6, g); R(2.2, 4.2, 5.6, 1.6, g); },
    resources: () => { for (let i = 0; i < 4; i++) R(2.2 + i * 1.6, 7.6 - [2, 4, 3, 5][i], 1.1, [2, 4, 3, 5][i], g); },
    updates: () => { R(4.3, 2, 1.4, 4.2, g); c.line(Math.round(x + 2.6 * u), Math.round(y + 5 * u), Math.round(cx), Math.round(y + 7.6 * u), g); c.line(Math.round(x + 7.4 * u), Math.round(y + 5 * u), Math.round(cx), Math.round(y + 7.6 * u), g); },
    backup: () => { R(2.2, 2.6, 5.6, 1.6, g); R(2.6, 4.4, 4.8, 3.2, g); R(4.2, 5.2, 1.6, 0.6, d); },
    security: () => { R(2.6, 2.4, 4.8, 3.4, g); R(3.4, 5.8, 3.2, 1.4, g); R(4.4, 3.8, 1.2, 1.6, d); },
    calculator: () => { R(2.6, 1.8, 4.8, 6.4, g); R(3.2, 2.4, 3.6, 1.4, d); for (let i = 0; i < 6; i++) R(3.2 + (i % 3) * 1.3, 4.4 + Math.floor(i / 3) * 1.6, 0.9, 1, d); },
    browser: () => { circle(c, Math.round(cx), Math.round(cy), Math.round(3.2 * u), g); circle(c, Math.round(cx), Math.round(cy), Math.round(2.6 * u), base); R(4.8, 2, 0.5, 6, g); R(2, 4.8, 6, 0.5, g); },
    notes: () => { R(2.6, 2.2, 4.8, 5.8, g); R(3.4, 3.6, 3.2, 0.5, d); R(3.4, 4.8, 3.2, 0.5, d); },
    clock: () => { ring(c, Math.round(cx), Math.round(cy), Math.round(3.2 * u), g); c.line(Math.round(cx), Math.round(cy), Math.round(cx), Math.round(cy - 2.2 * u), g); c.line(Math.round(cx), Math.round(cy), Math.round(cx + 1.8 * u), Math.round(cy), g); },
    'app-library': () => { for (let i = 0; i < 4; i++) R(2.4 + (i % 2) * 2.8, 2.4 + Math.floor(i / 2) * 2.8, 2.2, 2.2, g); },
  };
  (P[name] || (() => { const L = (name[0] || '?').toUpperCase(); c.text(Math.round(cx - 3 * (s / 24)), Math.round(cy - 3.5 * (s / 24)), L, g, Math.max(1, Math.round(s / 12))); }))();
}


const ACCENT = '#0078d4';        // KOS Blue
let look = 'normal';
/** Apps call this with `app.look` before drawing: icons and buttons get deeper in the 3D look. */
function setLook(l) { look = l; }

/** The default wallpaper: a bright blue sky and three sweeping layered waves, all from code. */
function wallpaper(c, w, h) {
  const band = Math.max(2, Math.round(h / 180));
  for (let y = 0; y < h; y += band) c.rect(0, y, w, band, mix('#38b6ff', '#0a6fd0', Math.min(1, y / h)));      // sky: light to KOS Blue
  const step = Math.max(2, Math.round(w / 360));
  const wave = (base, amp, k, phase, top, bottom, edge) => {
    for (let x = 0; x < w; x += step) {
      const yb = Math.round(h * base + h * amp * Math.sin(x * k + phase) + h * amp * 0.45 * Math.sin(x * k * 2.3 + phase * 1.7));
      c.rect(x, yb, step, 3, edge);                                                                                // a lit edge on the crest
      const span = h - yb - 3, rows = 4;
      for (let i = 0; i < rows; i++) c.rect(x, yb + 3 + Math.floor(span * i / rows), step, Math.ceil(span / rows) + 1, mix(top, bottom, i / (rows - 1)));
    }
  };
  wave(0.52, 0.07, 0.0042, 0.6, '#2b9bf0', '#0a63c4', '#9fdcff');
  wave(0.66, 0.06, 0.0051, 2.4, '#0f84e0', '#0750a8', '#6cc4ff');
  wave(0.80, 0.045, 0.0063, 4.1, '#0078d4', '#05468f', '#4fb3ff');
}

module.exports = { setLook, rgb, color, mix, lighten, darken, hue, gradV, roundRect, roundGradient, circle, ring, text, stext, stextCentered, textWidth, textCentered, button, icon, wallpaper, ACCENT };

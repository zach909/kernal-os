'use strict';
// HTML to readable text, with the links numbered. Deliberately small: no scripts, no styles, no images - the page's
// words, in order, with structure kept where it helps (headings, paragraphs, lists). Pure functions, easy to test.

const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', copy: '(c)', hellip: '...', mdash: '-', ndash: '-', rsquo: "'", lsquo: "'", rdquo: '"', ldquo: '"', bull: '*', middot: '.', laquo: '<<', raquo: '>>' };

function decode(s) {
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e) => {
    if (e[0] === '#') {
      const n = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return Number.isFinite(n) && n > 31 && n < 0x110000 ? String.fromCodePoint(n) : ' ';
    }
    return ENTITIES[e.toLowerCase()] ?? m;
  });
}

function resolve(href, base) {
  try {
    const u = new URL(href, base);
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.href : null;     // never javascript:, data:, file: ...
  } catch { return null; }
}

/** -> { title, text, links: [{n, url, label}] } ; `text` has [n] after each link's words. */
function htmlToText(html, base) {
  const links = [];
  let h = String(html).slice(0, 2_000_000);
  const t = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(h);
  const title = t ? decode(t[1]).replace(/\s+/g, ' ').trim().slice(0, 120) : '';
  h = h.replace(/<!--[\s\S]*?-->/g, '').replace(/<(script|style|noscript|template|svg|head)\b[\s\S]*?<\/\1\s*>/gi, ' ');
  h = h.replace(/<a\b([^>]*)>([\s\S]*?)<\/a\s*>/gi, (m, attrs, inner) => {
    const href = /href\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(attrs);
    const url = href ? resolve(decode(href[2] ?? href[3] ?? href[4] ?? ''), base) : null;
    const label = decode(inner.replace(/<[^>]*>/g, ' ')).replace(/\s+/g, ' ').trim();
    if (!url || !label) return ` ${inner} `;
    let n = links.findIndex((l) => l.url === url) + 1;
    if (!n) { links.push({ n: links.length + 1, url, label: label.slice(0, 80) }); n = links.length; }
    return ` ${label}[${n}] `;
  });
  h = h.replace(/<(h[1-6])\b[^>]*>([\s\S]*?)<\/\1\s*>/gi, (m, tag, inner) => `\n\n${inner.replace(/<[^>]*>/g, ' ').trim().toUpperCase()}\n\n`);
  h = h.replace(/<li\b[^>]*>/gi, '\n * ').replace(/<br\s*\/?>/gi, '\n').replace(/<\/(p|div|section|article|tr|table|ul|ol|blockquote|pre|header|footer|nav|main|form)\s*>/gi, '\n\n');
  h = h.replace(/<(p|div|section|article|table|ul|ol|blockquote|pre|tr)\b[^>]*>/gi, '\n').replace(/<[^>]*>/g, ' ');
  const lines = decode(h).split('\n').map((l) => l.replace(/[ \t\r\f\v]+/g, ' ').trim());
  const text = lines.join('\n').replace(/\n{3,}/g, '\n\n').trim();
  return { title, text, links };
}

function wrap(text, width) {
  const out = [];
  for (const para of text.split('\n')) {
    if (!para) { out.push(''); continue; }
    const indent = para.startsWith(' * ') ? '   ' : '';
    let line = '';
    for (const w of para.split(' ')) {
      if (line && (line + ' ' + w).length > width) { out.push(line); line = indent + w; } else line = line ? line + ' ' + w : w;
      while (line.length > width) { out.push(line.slice(0, width)); line = indent + line.slice(width); }
    }
    out.push(line);
  }
  return out;
}

module.exports = { htmlToText, wrap, decode, resolve };

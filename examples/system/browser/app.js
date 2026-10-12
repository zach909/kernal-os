'use strict';
// A text-mode web browser. It fetches a page over http(s) (the OS gave it network only because you allowed it),
// turns the HTML into readable text with numbered links, and shows it in a text window. It runs no scripts and shows
// no images - so there is little for a hostile page to do. Keys: g go to an address, 1-9... then Enter follows a
// numbered link, b back, r reload, up/down/pgup/pgdn scroll, Esc leaves a prompt.
const http = require('http');
const https = require('https');
const path = require('path');
const { App } = require(process.env.KOS_SDK_JS);
const { htmlToText, wrap, resolve } = require('./text.js');
const MAX_BYTES = 2_000_000, MAX_REDIRECTS = 5, TIMEOUT_MS = 10_000;

function fetchPage(url, hops = 0) {
  return new Promise((resolveP, reject) => {
    const u = new URL(url);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return reject(new Error('only http and https addresses'));
    const lib = u.protocol === 'https:' ? https : http;
    const req = lib.get(u, { headers: { 'user-agent': 'KOS-text-browser/1.0', accept: 'text/html,text/plain;q=0.9' }, timeout: TIMEOUT_MS }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        if (hops >= MAX_REDIRECTS) return reject(new Error('too many redirects'));
        const next = resolve(res.headers.location, u.href);
        return next ? fetchPage(next, hops + 1).then(resolveP, reject) : reject(new Error('redirect to something that is not a web address'));
      }
      const type = String(res.headers['content-type'] || '');
      if (!/^text\/|xhtml|xml/i.test(type) && type) { res.resume(); return reject(new Error(`this is ${type.split(';')[0]}, not a web page I can show`)); }
      const chunks = []; let n = 0;
      res.on('data', (c) => { n += c.length; if (n > MAX_BYTES) { req.destroy(new Error('page is larger than 2 MB')); } else chunks.push(c); });
      res.on('end', () => resolveP({ url: u.href, status: res.statusCode, type, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('timeout', () => req.destroy(new Error('timed out after 10 s')));
    req.on('error', reject);
  });
}

(async () => {
  const app = new App();
  const st = { page: null, lines: [], links: [], scroll: 0, history: [], prompt: null, num: '', note: 'g: enter an address', loading: false };
  const render = () => {
    const w = Math.max(20, app.width - 2), rows = Math.max(3, app.height - 4);
    const head = st.page ? `${st.page.title || st.page.url}` : 'KOS browser';
    const body = st.lines.slice(st.scroll, st.scroll + rows);
    const lines = [head.slice(0, w), (st.page ? st.page.url : '').slice(0, w), ...body];
    while (lines.length < rows + 2) lines.push('');
    const status = st.prompt !== null ? `go to: ${st.prompt}_` : st.num ? `link: ${st.num}_  (Enter follows)` : st.loading ? 'loading...' : st.note;
    app.screen('Browser', lines.map((l) => ` ${l}`), status);
  };
  const show = (page) => {
    const conv = /html|xml/i.test(page.type) || /<html|<body|<p[ >]/i.test(page.body.slice(0, 2000)) ? htmlToText(page.body, page.url) : { title: '', text: page.body, links: [] };
    st.page = { url: page.url, title: conv.title, body: page.body, type: page.type }; st.links = conv.links; st.scroll = 0;
    st.lines = wrap(conv.text || '(an empty page)', Math.max(20, app.width - 4));
    if (conv.links.length) st.lines.push('', '--- links ---', ...conv.links.map((l) => `[${l.n}] ${l.label}  ${l.url}`.slice(0, Math.max(20, app.width - 4))));
    st.note = `${page.status}  ${conv.links.length} link(s)   g go  b back  r reload`;
  };
  const load = async (url, push = true) => {
    st.loading = true; render();
    try {
      const page = await fetchPage(url);
      if (push && st.page) st.history.push(st.page.url);
      show(page);
    } catch (e) { st.note = `could not load: ${e.message}`.slice(0, 120); }
    st.loading = false; render();
  };
  for await (const ev of app.events()) {
    if (ev.cmd === 'hello') { render(); continue; }
    if (ev.cmd === 'launch' && ev.command === 'open-url' && ev.line) { const u = resolve(ev.line, 'http://x/'); if (u && /^https?:\/\//i.test(ev.line)) await load(ev.line); else st.note = 'that is not an http(s) address'; render(); continue; }
    if (ev.cmd !== 'key') continue;
    const k = ev.key;
    if (st.prompt !== null) {
      if (k === 'escape') st.prompt = null;
      else if (k === 'backspace') st.prompt = st.prompt.slice(0, -1);
      else if (k === 'enter') { const raw = st.prompt.trim(); st.prompt = null; const u = /^https?:\/\//i.test(raw) ? raw : raw ? `https://${raw}` : ''; if (u) { await load(u); continue; } }
      else if (k.length === 1) st.prompt += k;
    } else if (/^[0-9]$/.test(k)) st.num += k;
    else if (k === 'enter' && st.num) { const l = st.links.find((x) => x.n === Number(st.num)); st.num = ''; if (l) { await load(l.url); continue; } st.note = 'no such link'; }
    else if (k === 'escape') st.num = '';
    else if (k === 'backspace') st.num = st.num.slice(0, -1);
    else if (k === 'g') st.prompt = '';
    else if (k === 'b' && st.history.length) { await load(st.history.pop(), false); continue; }
    else if (k === 'r' && st.page) { await load(st.page.url, false); continue; }
    else if (k === 'down') st.scroll = Math.min(Math.max(0, st.lines.length - 1), st.scroll + 1);
    else if (k === 'up') st.scroll = Math.max(0, st.scroll - 1);
    else if (k === 'pagedown' || k === ' ') st.scroll = Math.min(Math.max(0, st.lines.length - 1), st.scroll + Math.max(3, app.height - 5));
    else if (k === 'pageup') st.scroll = Math.max(0, st.scroll - Math.max(3, app.height - 5));
    else if (k === 'home') st.scroll = 0;
    render();
  }
})();

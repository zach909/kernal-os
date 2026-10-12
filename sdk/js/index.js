'use strict';
// The app side of the KOS command protocol for Node. Standard library only.
//
//   const { App, Canvas } = require(process.env.KOS_SDK_JS);
//   (async () => {
//     const app = new App();
//     for await (const ev of app.events()) {
//       if (ev.cmd === 'hello') app.screen('Hello', ['from Node']);
//     }
//   })();
//
// The first event is always {cmd:'hello'}. An app never touches a device, the
// terminal or the screen: it answers the OS's commands with commands.

const net = require('net');
const fs = require('fs');
const path = require('path');
const readline = require('readline');

class Canvas {
  constructor() { this.ops = []; }
  clear(color) { this.ops.push(['clear', color]); return this; }
  rect(x, y, w, h, color) { this.ops.push(['rect', Math.round(x), Math.round(y), Math.round(w), Math.round(h), color]); return this; }
  line(x0, y0, x1, y1, color) { this.ops.push(['line', Math.round(x0), Math.round(y0), Math.round(x1), Math.round(y1), color]); return this; }
  hit(x, y, w, h, label) { this.ops.push(['hit', Math.round(x), Math.round(y), Math.round(w), Math.round(h), String(label)]); return this; }
  poly(pts, color, alpha = 255) { this.ops.push(['poly', pts.map(([x, y]) => [Math.round(x * 100) / 100, Math.round(y * 100) / 100]), color, alpha]); return this; }
  stext(x, y, s, color, px = 14, face = 0) { this.ops.push(['stext', Math.round(x), Math.round(y), String(s), color, Math.round(px), face]); return this; }
  text(x, y, s, color, scale = 1) { this.ops.push(['text', Math.round(x), Math.round(y), String(s), color, scale]); return this; }
}

class App {
  constructor() {
    const fd = Number(process.env.KOS_CHANNEL_FD);
    if (!Number.isInteger(fd)) throw new Error('KOS_CHANNEL_FD is not set: run this app under KOS');
    this.sock = new net.Socket({ fd, readable: true, writable: true });
    this.sock.on('error', () => process.exit(0));
    this.mode = process.env.KOS_MODE || 'tui';
    this.width = 80;
    this.height = 24;
    this.scale = 1;
    this.insets = [0, 0, 0, 0];
    this.font = {};
    this.look = 'normal';
    this.options = {};
    this.devices = new Set();
  }

  // Pixel width of smooth text, from the advances the OS sent in hello.
  textWidth(s, px = 14, face = 0) {
    const adv = (this.font[['sans', 'bold', 'mono'][face]] || {}).adv;
    if (!adv) return Math.round(String(s).length * px * 0.55);
    let w = 0;
    for (const c of String(s)) { const o = c.codePointAt(0); w += o >= 32 && o < 127 ? adv[o - 32] : 600; }
    return Math.round(w * px / 1000);
  }

  send(obj) { this.sock.write(JSON.stringify(obj) + '\n'); }

  async *events() {
    const rl = readline.createInterface({ input: this.sock, crlfDelay: Infinity });
    for await (const line of rl) {
      let ev;
      try { ev = JSON.parse(line); } catch { continue; }
      if (ev.cmd === 'hello') {
        this.mode = ev.mode || this.mode;
        this.width = ev.width || this.width;
        this.height = ev.height || this.height;
        this.scale = ev.scale || this.scale;
        this.insets = ev.insets || this.insets;
        this.font = ev.font || this.font;
        this.look = ev.look || this.look;
        this.options = ev.options || this.options;
        try { require('./gfx.js').setLook(this.look); } catch { /* an app may not use the drawing kit */ }
      } else if (ev.cmd === 'look') {
        this.look = ev.look || this.look;
        this.options = ev.options || this.options;
        try { require('./gfx.js').setLook(this.look); } catch { /* ditto */ }
      } else if (ev.cmd === 'device' && ev.state === 'attached') {
        this.devices.add(ev.device);
      } else if (ev.cmd === 'quit') {
        return;
      }
      yield ev;
    }
  }

  // commands the app can issue
  screen(title, lines, status = '') { this.send({ cmd: 'screen', title, lines, status }); }
  present(canvas) { this.send({ cmd: 'frame', ops: canvas.ops }); }
  log(msg) { this.send({ cmd: 'log', msg: String(msg) }); }
  exit(code = 0) { this.send({ cmd: 'exit', code }); }

  // asking the OS for things (needs the 'system' permission); answers arrive as events
  requestApps() { this.send({ cmd: 'request', action: 'apps' }); }
  requestOpen(app, mode = 'tui', command = '', line = '', opts = {}) { this.send({ cmd: 'request', action: 'open', app, mode, ...(command ? { command } : {}), ...(line ? { line } : {}), ...(opts.new ? { new: true } : {}), ...(opts.background ? { background: true } : {}) }); }
  requestFocus(id) { this.send({ cmd: 'request', action: 'focus', id }); }
  requestClose(id) { this.send({ cmd: 'request', action: 'close', id }); }
  requestInfo() { this.send({ cmd: 'request', action: 'info' }); }
  requestLs(p) { this.send({ cmd: 'request', action: 'ls', path: p }); }
  requestView(p) { this.send({ cmd: 'request', action: 'view', path: p }); }
  requestScan(p) { this.send({ cmd: 'request', action: 'scan', path: p }); }
  requestOptimize() { this.send({ cmd: 'request', action: 'optimize' }); }
  requestSettle() { this.send({ cmd: 'request', action: 'settle' }); }
  requestPermit(app, revoke = false) { this.send({ cmd: 'request', action: revoke ? 'revoke' : 'permit', app }); }
  requestLine(text) { this.send({ cmd: 'request', action: 'line', text }); }
  requestSave(p, text) { this.send({ cmd: 'request', action: 'save', path: p, text }); }
  requestBackup(p) { this.send({ cmd: 'request', action: 'backup', path: p }); }
  requestBackups() { this.send({ cmd: 'request', action: 'backups' }); }
  requestRestore(backup, member, to) { this.send({ cmd: 'request', action: 'restore', backup, member, to }); }
  requestPush(backup) { this.send({ cmd: 'request', action: 'push', backup }); }
  requestRemote(url) { this.send({ cmd: 'request', action: 'remote', url }); }
  requestSys(kind, arg = '') { this.send({ cmd: 'request', action: 'sys', kind, arg }); }
  requestSignal(pid, sig) { this.send({ cmd: 'request', action: 'signal', pid, sig }); }
  requestRenice(pid, nice) { this.send({ cmd: 'request', action: 'renice', pid, nice }); }
  requestFsChange(op, p, extra = {}) { this.send({ cmd: 'request', action: 'fschange', op, path: p, ...extra }); }
  requestUpdates(op, extra = {}) { this.send({ cmd: 'request', action: 'updates', op, ...extra }); }
  requestAnimate(on) { this.send({ cmd: 'request', action: 'animate', on: !!on }); }
  requestLook(opts = {}) { this.send({ cmd: 'request', action: 'look', op: Object.keys(opts).length ? 'set' : 'get', ...opts }); }
  requestToggle(app) { this.send({ cmd: 'request', action: 'toggle', app }); }
  requestNotify(title, body = '') { this.send({ cmd: 'request', action: 'notify', op: 'post', title, body }); }
  requestNotifyClear() { this.send({ cmd: 'request', action: 'notify', op: 'clear' }); }
  requestNotifyDismiss(id) { this.send({ cmd: 'request', action: 'notify', op: 'dismiss', id }); }
  requestKeys(on) { this.send({ cmd: 'request', action: 'keys', on: !!on }); }
  requestWorkspace(n, id = '') { this.send({ cmd: 'request', action: 'workspace', n, ...(id ? { id } : {}) }); }
  requestTab(name) { this.send({ cmd: 'request', action: 'tab', name }); }
  requestLinks(op = 'list', fields = {}) { this.send({ cmd: 'request', action: 'links', op, ...fields }); }
  requestOpenLink(id) { this.send({ cmd: 'request', action: 'openlink', id }); }
  requestQuantum(op = 'devices', fields = {}) { this.send({ cmd: 'request', action: 'quantum', op, ...fields }); }
  requestAutoUpdate(op = 'status', fields = {}) { this.send({ cmd: 'request', action: 'autoupdate', op, ...fields }); }
  requestHeal(op = 'check') { this.send({ cmd: 'request', action: 'heal', op }); }
  requestMods(op = 'list', name = '') { this.send({ cmd: 'request', action: 'mods', op, ...(op !== 'list' ? { name } : {}) }); }
  requestPolicy(op = 'get', iface = '') { this.send({ cmd: 'request', action: 'policy', op, ...(op === 'set' ? { interface: iface } : {}) }); }
  requestSudo(op = 'status', minutes = 5, layers = ['interface', 'app', 'command']) { this.send({ cmd: 'request', action: 'sudo', op, ...(op === 'open' ? { minutes, layers } : {}) }); }
  requestResize(w = 0, h = 0) { this.send({ cmd: 'request', action: 'resize', ...(w ? { w: Math.round(w) } : {}), ...(h ? { h: Math.round(h) } : {}) }); }
  requestLayout(order, hidden) { this.send({ cmd: 'request', action: 'layout', order, hidden }); }
  requestNetCheck() { this.send({ cmd: 'request', action: 'netcheck' }); }

  cacheDir() { return process.env.KOS_CACHE_DIR || null; }

  /** Read a file shipped inside this app (it was unpacked read-only into RAM). */
  resource(name) {
    const root = path.resolve(process.env.KOS_APP_DIR || '.');
    const full = path.resolve(root, name);
    if (full !== root && !full.startsWith(root + path.sep)) throw new Error('outside the app');
    return fs.readFileSync(full);
  }
}

module.exports = { App, Canvas };

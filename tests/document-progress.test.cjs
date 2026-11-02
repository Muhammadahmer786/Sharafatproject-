const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

function setup(mode = 'protect') {
  const file = path.join(__dirname, '../sentinel/static/document-progress.js');
  assert.ok(fs.existsSync(file), 'Document progress controller must exist');
  const jar = new Map(), timers = new Map(), listeners = new Map();
  let now = 0, random = 0, timer = 0;
  function node() {return {hidden: true, textContent: '', innerHTML: 'Original button', disabled: false,
    value: '', dataset: {}, attrs: {},
    setAttribute(name, value) {this.attrs[name] = String(value);},
    removeAttribute(name) {delete this.attrs[name];}};}
  const nodes = Object.fromEntries(['[data-progress-panel]', '[data-progress-bar]', '[data-progress-status]',
    '[data-progress-detail]', '[name="download_token"]', 'button[type="submit"]', '.form-feedback'].map(key => [key, node()]));
  const form = {dataset: {documentProgress: mode}, querySelector: key => nodes[key]};
  const document = {};
  Object.defineProperty(document, 'cookie', {
    get: () => [...jar].map(([name, value]) => `${name}=${value}`).join('; '),
    set: value => {const first = value.split(';')[0]; const [name, content] = first.split('=');
      if (value.includes('Max-Age=0')) jar.delete(name); else jar.set(name, content);}
  });
  const window = {addEventListener: (name, fn) => listeners.set(name, fn),
    removeEventListener: (name, fn) => {if (listeners.get(name) === fn) listeners.delete(name);}};
  const context = {window, document, location: {pathname: '/' + mode}, Date: {now: () => now},
    crypto: {getRandomValues(bytes) {bytes.fill(++random); return bytes;}},
    setInterval: fn => {timers.set(++timer, fn); return timer;}, clearInterval: id => timers.delete(id)};
  vm.runInNewContext(fs.readFileSync(file, 'utf8'), context);
  return {form, nodes, jar, timers, listeners, start: event => window.SentinelDocumentProgress.start(form, event),
    tick(ms = 0) {now += ms; [...timers.values()].forEach(fn => fn());}};
}

for (const mode of ['protect', 'recover']) test(mode + ' shows an indeterminate progress bar, then confirms only its download', () => {
  const h = setup(mode);
  let blocked = false;
  h.start({preventDefault() {blocked = true;}});
  assert.equal(blocked, false, 'native submission must proceed');
  assert.equal(h.nodes['[data-progress-panel]'].hidden, false);
  assert.equal(h.nodes['[data-progress-panel]'].dataset.state, 'working');
  assert.equal(h.nodes['[data-progress-bar]'].attrs['aria-valuenow'], undefined);
  assert.match(h.nodes['[data-progress-status]'].textContent, mode === 'protect' ? /Protecting/ : /Recovering/);
  assert.equal(h.nodes['button[type="submit"]'].disabled, true);
  const token = h.nodes['[name="download_token"]'].value;
  assert.match(token, /^[0-9a-f]{32}$/);
  h.jar.set('sentinel_download_' + 'ff'.repeat(16), 'ready');
  h.tick(); assert.equal(h.nodes['[data-progress-panel]'].dataset.state, 'working');
  h.jar.set('sentinel_download_' + token, 'ready'); h.tick();
  assert.equal(h.nodes['[data-progress-panel]'].dataset.state, 'ready');
  assert.equal(h.nodes['[data-progress-status]'].textContent, 'Download started');
  assert.equal(h.nodes['[data-progress-bar]'].attrs['aria-valuenow'], '100');
  assert.equal(h.nodes['button[type="submit"]'].disabled, false);
  assert.equal(h.jar.has('sentinel_download_' + token), false);
  assert.equal(h.timers.size, 0);
});

test('duplicate clicks are blocked and a later submission gets a new marker', () => {
  const h = setup(); h.start({preventDefault() {assert.fail('first submission blocked');}});
  const first = h.nodes['[name="download_token"]'].value;
  let blocked = false; h.start({preventDefault() {blocked = true;}});
  assert.ok(blocked); assert.equal(h.timers.size, 1);
  h.jar.set('sentinel_download_' + first, 'ready'); h.tick();
  h.start({preventDefault() {assert.fail('next submission blocked');}});
  assert.notEqual(h.nodes['[name="download_token"]'].value, first);
  assert.equal(h.nodes['[data-progress-bar]'].attrs['aria-valuenow'], undefined);
});

test('missing confirmation times out without claiming a download or leaving controls stuck', () => {
  const h = setup(); h.start({preventDefault() {}}); h.tick(300001);
  assert.equal(h.nodes['[data-progress-panel]'].dataset.state, 'waiting');
  assert.match(h.nodes['[data-progress-status]'].textContent, /waiting/i);
  assert.equal(h.nodes['[data-progress-bar]'].attrs['aria-valuenow'], undefined);
  assert.equal(h.nodes['button[type="submit"]'].disabled, false);
  assert.equal(h.timers.size, 0);
});

test('page departure clears polling and restores controls for history navigation', () => {
  const h = setup(); h.start({preventDefault() {}});
  h.listeners.get('pagehide')();
  assert.equal(h.timers.size, 0);
  assert.equal(h.nodes['button[type="submit"]'].disabled, false);
});

test('app submission validates before progress and leaves other downloads on their native path', () => {
  const source = fs.readFileSync(path.join(__dirname, '../sentinel/static/app.js'), 'utf8');
  const code = source.slice(source.indexOf('document.querySelectorAll("[data-download-form]")'),
    source.indexOf('document.querySelectorAll("[data-processing-form]")'));
  let listener, valid = false, starts = 0, documentForm = true;
  const feedback = {hidden: true, textContent: ''};
  const form = {hasAttribute: name => name === 'data-max-request-bytes' || (documentForm && name === 'data-document-progress'),
    querySelector: () => feedback, addEventListener: (_, fn) => {listener = fn;}};
  vm.runInNewContext(code, {document: {querySelectorAll: () => [form]},
    validateFileLimits: () => valid,
    window: {SentinelDocumentProgress: {start() {starts++; return true;}}}});
  let prevented = false;
  listener({preventDefault() {prevented = true;}});
  assert.ok(prevented); assert.equal(starts, 0);
  valid = true; prevented = false;
  listener({preventDefault() {prevented = true;}});
  assert.equal(prevented, false); assert.equal(starts, 1);
  assert.equal(feedback.hidden, true, 'document controller owns the status');
  documentForm = false;
  listener({submitter: {value: 'view'}, preventDefault() {assert.fail('key view blocked');}});
  assert.equal(starts, 1); assert.match(feedback.textContent, /Verifying your identity/);
});

test('unavailable random source falls back without preventing the native form', () => {
  const source = fs.readFileSync(path.join(__dirname, '../sentinel/static/document-progress.js'), 'utf8');
  const context = {window: {}, crypto: {getRandomValues() {throw new Error('unavailable');}}};
  vm.runInNewContext(source, context);
  assert.equal(context.window.SentinelDocumentProgress.start({}, {preventDefault() {assert.fail('submission blocked');}}), false);
});

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

function loadState() {
  const file = path.join(__dirname, '../sentinel/static/analysis-updates.js');
  assert.ok(fs.existsSync(file), 'Analysis updates client must exist');
  return require(file).UpdatesState;
}
const pending = (id='one') => ({id, state:'queued', revision:'queued:1'});
const ready = (id='one', revision='complete:2') => ({id, state:'complete', revision});

test('initial snapshot lists recent results without replaying old alerts', () => {
  const State=loadState(), state=new State();
  assert.deepEqual(state.ingest([pending(),ready('old')]), []);
  assert.equal(state.unread(ready('old')), true);
  assert.equal(state.unread(pending()), false);
});
test('completion alerts once across page navigation and can be marked read', () => {
  const State=loadState(), state=new State();
  state.ingest([pending()]);
  assert.deepEqual(state.ingest([ready()]), [ready()]);
  assert.deepEqual(state.ingest([ready()]), []);
  state.markRead('one',ready().revision);
  const next=new State(state.serialize());
  assert.deepEqual(next.ingest([ready()]), []);
  assert.equal(next.unread(ready()), false);
});
test('completion during navigation and new revisions notify without treating pending as complete', () => {
  const State=loadState(), first=new State(); first.ingest([pending()]);
  const next=new State(first.serialize());
  assert.equal(next.ingest([ready()]).length,1);
  assert.deepEqual(next.ingest([pending()]),[]);
  assert.equal(next.ingest([ready('one','complete:3')]).length,1);
});
test('failure is a terminal alert and refresh creates a new unread revision', () => {
  const State=loadState(), state=new State(); state.ingest([pending()]);
  const failure={id:'one',state:'failed',revision:'failed:2'};
  assert.deepEqual(state.ingest([failure]),[failure]);
  state.markRead('one','failed:2');
  state.ingest([pending()]); state.ingest([ready()]);
  assert.equal(state.unread(ready()),true);
});
test('storage is bounded and contains no indicators, URLs or result data', () => {
  const State=loadState(), state=new State('invalid json');
  state.ingest(Array.from({length:150},(_,n)=>({...ready(String(n)),target:'sensitive target',url:'https://sensitive.example',result:{private:true}})));
  const serialized=state.serialize(), saved=JSON.parse(serialized);
  assert.ok(Object.keys(saved.records).length<=100);
  assert.ok(!serialized.includes('sensitive') && !serialized.includes('private'));
});
test('separate account state does not inherit another account read flags', () => {
  const State=loadState(), first=new State(); first.ingest([ready()]); first.markRead('one',ready().revision);
  const other=new State(); other.ingest([ready()]);
  assert.equal(first.unread(ready()),false); assert.equal(other.unread(ready()),true);
});
test('read flags merge monotonically for matching revisions across tabs',()=>{
  const State=loadState(), first=new State();first.ingest([ready()]);
  const second=new State(first.serialize());first.markRead('one',ready().revision);
  assert.equal(typeof second.mergeRead,'function','cross-tab reads need a monotonic merge');
  second.mergeRead(first.serialize());assert.equal(second.unread(ready()),false);
  const stale=new State();stale.ingest([ready()]);second.mergeRead(stale.serialize());
  assert.equal(second.unread(ready()),false,'a stale unread snapshot cannot undo a read');
  second.ingest([ready('one','complete:3')]);second.mergeRead(first.serialize());
  assert.equal(second.unread(ready('one','complete:3')),true,'an older read must not hide a newer result');
});
test('interrupted and cancelled AI jobs notify with truthful terminal states', () => {
  for (const status of ['interrupted', 'cancelled']) {
    const State = loadState(), state = new State();
    const running = {id:'job',state:'running',revision:'running:1'};
    state.ingest([running]);
    const terminal = {id:'job',state:status,revision:status+':2'};
    assert.deepEqual(state.ingest([terminal]), [terminal]);
    assert.equal(state.unread(terminal), true);
  }
});

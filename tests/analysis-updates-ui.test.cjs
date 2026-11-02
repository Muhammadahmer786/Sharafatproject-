// DOM and fetch/timer stubs exercise the real client; these are not browser tests.
const test=require('node:test'), assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'../sentinel/static/analysis-updates.js'),'utf8');
const id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const item=(state='queued',extra={})=>({id,kind:'url',kind_label:'URL',target:'https://example.test/',
  state,revision:state+':1',label:state==='queued'?'In progress':'Analysis complete',tone:state==='queued'?'working':'ready',url:'/intelligence/'+id,...extra});
const response=(items,extra={})=>({ok:true,status:200,redirected:false,json:async()=>({owner:'owner:1',items,active_count:items.filter(row=>row.state==='queued').length}),...extra});
function node(){return {hidden:true,textContent:'',className:'',dataset:{},attrs:{},children:[],events:{},
  setAttribute(k,v){this.attrs[k]=String(v);},removeAttribute(k){delete this.attrs[k];},
  append(...nodes){this.children.push(...nodes);},replaceChildren(...nodes){this.children=[...nodes];},
  addEventListener(k,fn){this.events[k]=fn;},focus(){this.focused=true;}};}
function setup(responses,{storageBroken=false,pending=false,watchAI=false}={}) {
  const nodes={},timers=new Map(),events={},windowEvents={},storage=new Map();let timerId=0,calls=0;
  const urls=[];
  const root=node(); root.dataset={owner:'owner:1',feedUrl:'/intelligence/updates',watch:pending?id:'',watchAi:watchAI?id:''};
  root.querySelector=selector=>nodes[selector]??=node();root.contains=target=>target===root;
  const detail=node(),heading=node(),paragraph=node(),link=node(),badge=node();
  detail.dataset.liveCheck=id;detail.querySelector=key=>({'h2':heading,'p':paragraph,'a':link}[key]);
  const document={hidden:false,querySelector:selector=>selector==='[data-analysis-updates]'?root:
    selector==='[data-live-check]'&&pending?detail:selector==='[data-current-check-badge]'?badge:null,
    createElement:()=>{const created=node();created.focus=()=>{document.activeElement=created;};return created;},addEventListener:(name,fn)=>{events[name]=fn;}};
  const context={document,window:{addEventListener:(name,fn)=>{windowEvents[name]=fn;}},AbortController,
    localStorage:{getItem:key=>{if(storageBroken)throw Error('blocked');return storage.get(key);},
      setItem:(key,value)=>{if(storageBroken)throw Error('blocked');storage.set(key,value);}},
    fetch:async(url)=>{calls++;urls.push(url);const next=responses.shift();if(next instanceof Error)throw next;assert.ok(next,'unexpected fetch');return next;},
    setTimeout:(fn,ms)=>{timers.set(++timerId,{fn,ms});return timerId;},clearTimeout:id=>timers.delete(id)};
  vm.runInNewContext(source,context);
  const flush=()=>new Promise(resolve=>setImmediate(resolve));
  return {nodes,root,detail,heading,paragraph,link,badge,document,events,windowEvents,timers,storage,urls,
    calls:()=>calls,flush,async poll(){const timer=[...timers].find(([,value])=>value.ms===10000);assert.ok(timer,'next poll scheduled');timers.delete(timer[0]);await timer[1].fn();await flush();}};
}

test('pending-to-complete displays a clickable toast and updates the pending detail without navigation',async()=>{
  const h=setup([response([item()]),response([item('complete',{target:'<img src=x onerror=alert(1)>'})])],{pending:true});await h.flush();
  assert.equal(h.nodes['[data-updates-toast]'].hidden,true);
  await h.poll();
  assert.equal(h.nodes['[data-updates-toast]'].hidden,false);
  assert.equal(h.nodes['[data-toast-title]'].textContent,'Analysis complete');
  assert.equal(h.nodes['[data-toast-link]'].href,'/intelligence/'+id);
  assert.equal(h.heading.textContent,'Analysis complete');assert.equal(h.link.href,'/intelligence/'+id);
  assert.match(h.nodes['[data-toast-detail]'].textContent,/<img/,'untrusted target remains literal text');
  assert.equal(h.nodes['[data-updates-list]'].children[0].href,'/intelligence/'+id);
  h.nodes['[data-toast-link]'].events.click();
  assert.match(h.nodes['[data-updates-summary]'].textContent,/0 unread/);
});

test('hidden pages pause and resumed polling removes updates on account mismatch',async()=>{
  const switched=response([],{json:async()=>({owner:'other:1',items:[],active_count:0})});
  const h=setup([response([item()]),switched]);await h.flush();
  h.document.hidden=true;h.events.visibilitychange();
  assert.equal([...h.timers.values()].filter(x=>x.ms===10000).length,0);assert.equal(h.calls(),1);
  h.document.hidden=false;h.events.visibilitychange();await h.flush();
  assert.equal(h.nodes['[data-updates-list]'].children.length,0);
  assert.match(h.nodes['[data-updates-connection]'].textContent,/session changed or expired/);
  assert.equal(h.timers.size,0);
});

test('transient errors retry with honest status and auth redirects stop polling',async()=>{
  const h=setup([response([item()]),new Error('offline'),response([],{redirected:true})]);await h.flush();
  await h.poll();assert.match(h.nodes['[data-updates-connection]'].textContent,/last known status/);
  assert.equal(h.nodes['[data-updates-toast]'].hidden,true);
  await h.poll();assert.equal(h.timers.size,0);assert.equal(h.nodes['[data-updates-list]'].children.length,0);
});

test('blocked storage preserves in-memory alerts and unsafe URLs never become links',async()=>{
  const h=setup([response([item(),item('complete',{id:'other',url:'https://evil.example/'})]),response([item('complete')])],{storageBroken:true});await h.flush();
  assert.equal(h.nodes['[data-updates-list]'].children.length,1);
  await h.poll();assert.equal(h.nodes['[data-updates-toast]'].hidden,false);
});

test('panel opens with its button and Escape closes it with focus restored',async()=>{
  const h=setup([response([]),response([])]);await h.flush();
  h.nodes['[data-updates-toggle]'].events.click();await h.flush();
  assert.equal(h.nodes['[data-updates-panel]'].hidden,false);
  h.events.keydown({key:'Escape'});
  assert.equal(h.nodes['[data-updates-panel]'].hidden,true);
  assert.equal(h.nodes['[data-updates-toggle]'].focused,true);
});

test('unchanged background polls preserve the focused result link',async()=>{
  const h=setup([response([item()]),response([item()])]);await h.flush();
  const list=h.nodes['[data-updates-list]'], link=list.children[0];h.document.activeElement=link;
  await h.poll();assert.equal(list.children[0],link,'unchanged links should not be recreated');
  assert.equal(h.document.activeElement,link);
});

test('changed results restore focus to the same check and stale tab snapshots cannot undo read state',async()=>{
  const h=setup([response([item()]),response([item('complete')])]);await h.flush();
  h.document.activeElement=h.nodes['[data-updates-list]'].children[0];
  await h.poll();assert.equal(h.document.activeElement,h.nodes['[data-updates-list]'].children[0]);
  const key='sentinel-analysis-updates:owner:1';const stale=h.storage.get(key);
  h.nodes['[data-updates-read]'].events.click();
  h.storage.set(key,stale);h.windowEvents.storage({key,newValue:stale});
  assert.match(h.nodes['[data-updates-summary]'].textContent,/0 unread/);
  assert.equal(JSON.parse(h.storage.get(key)).records[id].read,true,'shared storage is repaired without resurrecting unread alerts');
});

test('local AI updates preserve provider watch queries and use only internal job links',async()=>{
  const ai=extra=>item('complete',{kind:'local_ai',kind_label:'Local AI',url:'/ai/'+id,...extra});
  const h=setup([response([ai(),ai({id:'unsafe',url:'/ai/../../settings'}),item('complete',{id:'provider'})])],{pending:true,watchAI:true});await h.flush();
  assert.equal(h.urls[0],'/intelligence/updates?watch='+id+'&watch_ai='+id);
  assert.equal(h.nodes['[data-updates-list]'].children.length,2);
  assert.equal(h.nodes['[data-updates-list]'].children[0].href,'/ai/'+id);
  assert.equal(h.nodes['[data-updates-list]'].children[1].href,'/intelligence/'+id);
});

test('mixed completion batches open the updates list so both local and provider results are reachable',async()=>{
  const local=state=>item(state,{id:'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',kind:'local_ai',kind_label:'Local AI',url:'/ai/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'});
  const h=setup([response([item(),local('queued')]),response([item('complete'),local('complete')])]);await h.flush();await h.poll();
  assert.equal(h.nodes['[data-toast-link]'].href,'#analysis-updates-panel');
  let prevented=false;h.nodes['[data-toast-link]'].events.click({preventDefault(){prevented=true;}});
  assert.equal(prevented,true);assert.equal(h.nodes['[data-updates-panel]'].hidden,false);
  assert.equal(h.nodes['[data-updates-list]'].children.length,2);
});

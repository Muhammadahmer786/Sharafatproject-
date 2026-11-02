// Execute the real controller with a small DOM and transport boundary; not a browser test.
const test=require('node:test'), assert=require('node:assert/strict');
const fs=require('node:fs'), path=require('node:path'), vm=require('node:vm');
const id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const status=(state='running',extra={})=>({id,state,stage:'decompiling',progress:25,error:'',result_url:'/ai/'+id,...extra});
const response=(body,extra={})=>({ok:true,status:200,redirected:false,json:async()=>body,...extra});
function node(){return {hidden:false,textContent:'',disabled:false,dataset:{},attrs:{},style:{},events:{},
  setAttribute(k,v){this.attrs[k]=String(v);},removeAttribute(k){delete this.attrs[k];},
  addEventListener(k,fn){this.events[k]=fn;}};}
function setup(responses,{state='queued',upload=false,valid=true}={}){
  const file=path.join(__dirname,'../sentinel/static/ai.js');
  assert.ok(fs.existsSync(file),'Local AI progress controller must exist');
  const nodes={},events={},windowEvents={},timers=new Map(),requests=[];let nextTimer=0;
  const root=node();root.dataset={aiJob:id,state,statusUrl:'/ai/'+id+'/status',resultUrl:'/ai/'+id};
  root.querySelector=selector=>nodes[selector]??=node();
  const steps=['queued','inspecting','decompiling','analysing','validating','complete'].map(step=>{const el=node();el.dataset.aiStep=step;return el;});
  root.querySelectorAll=()=>steps;
  const form=node();form.querySelector=selector=>nodes[selector]??=node();
  const document={hidden:false,querySelector:selector=>selector==='[data-ai-job]'&&!upload?root:selector==='[data-ai-upload]'&&upload?form:null,
    addEventListener:(event,fn)=>events[event]=fn};
  const context={document,window:{addEventListener:(event,fn)=>windowEvents[event]=fn},AbortController,
    validateFileLimits:()=>valid,
    fetch:async(url,options)=>{requests.push({url,options});const next=responses.shift();assert.ok(next,'unexpected status request');if(next instanceof Error)throw next;return next;},
    setTimeout:(fn,ms)=>{timers.set(++nextTimer,{fn,ms});return nextTimer;},clearTimeout:key=>timers.delete(key)};
  vm.runInNewContext(fs.readFileSync(file,'utf8'),context);
  const flush=()=>new Promise(resolve=>setImmediate(resolve));
  return {root,nodes,steps,events,windowEvents,timers,requests,document,form,flush,
    async poll(){const timer=[...timers].find(([,value])=>value.ms===3000);assert.ok(timer,'next status poll scheduled');timers.delete(timer[0]);await timer[1].fn();await flush();}};
}

test('server milestones update progress and completion ends polling with the local result link',async()=>{
  const h=setup([response(status()),response(status('complete',{stage:'complete',progress:100,result_url:'https://evil.test/'}))]);await h.flush();
  assert.equal(h.requests[0].url,'/ai/'+id+'/status');assert.equal(h.requests[0].options.cache,'no-store');
  assert.equal(h.nodes['[data-ai-progress]'].attrs['aria-valuenow'],'25');
  assert.match(h.nodes['[data-ai-stage]'].textContent,/Decompil/i);
  assert.equal(h.steps[2].attrs['aria-current'],'step');
  await h.poll();
  assert.equal(h.nodes['[data-ai-complete]'].hidden,false);
  assert.equal(h.nodes['[data-ai-result-link]'].href,'/ai/'+id);
  assert.equal(h.nodes['[data-ai-cancel]'].hidden,true);
  assert.equal(h.nodes['[data-ai-state]'].dataset.state,'complete');
  assert.equal(h.timers.size,0);
  h.windowEvents.pageshow();await h.flush();assert.equal(h.requests.length,2,'terminal jobs stay stopped after pageshow');
});

for(const state of ['failed','cancelled','interrupted'])test(state+' ends polling without a completed report',async()=>{
  const h=setup([response(status(state,{stage:state,progress:35,error:'<img src=x onerror=alert(1)>'}))]);await h.flush();
  assert.equal(h.nodes['[data-ai-complete]'].hidden,true);
  assert.equal(h.nodes['[data-ai-error]'].textContent,'<img src=x onerror=alert(1)>');
  assert.equal(h.nodes['[data-ai-cancel]'].hidden,true);assert.equal(h.timers.size,0);
  assert.equal(h.nodes['[data-ai-progress]'].attrs['aria-valuenow'],undefined);
  assert.doesNotMatch(h.nodes['[data-ai-stage]'].textContent,/complete|safe/i);
});

test('offline retry preserves the last known milestone and auth expiry stops requests',async()=>{
  const h=setup([response(status()),new Error('offline'),response(null,{status:401,ok:false})]);await h.flush();
  await h.poll();assert.match(h.nodes['[data-ai-live-message]'].textContent,/last known status/i);
  assert.equal(h.nodes['[data-ai-progress]'].attrs['aria-valuenow'],'25');
  await h.poll();assert.match(h.nodes['[data-ai-live-message]'].textContent,/session.*expired/i);assert.equal(h.timers.size,0);
});

test('hidden pages pause polling and invalid job responses never become completed results',async()=>{
  const h=setup([response(status()),response(status('complete',{id:'other',stage:'complete',progress:100}))]);await h.flush();
  h.document.hidden=true;h.events.visibilitychange();assert.equal(h.timers.size,0);
  h.document.hidden=false;h.events.visibilitychange();await h.flush();
  assert.equal(h.nodes['[data-ai-complete]'].hidden,true);
  assert.match(h.nodes['[data-ai-live-message]'].textContent,/last known status/i);
  assert.equal(h.nodes['[data-ai-progress]'].attrs['aria-valuenow'],'25');
});

test('already terminal detail pages make no status requests',async()=>{
  const h=setup([],{state:'complete'});await h.flush();assert.equal(h.requests.length,0);assert.equal(h.timers.size,0);
});

test('oversized uploads cannot disable submission or claim they are queued',()=>{
  const h=setup([],{upload:true,valid:false});let prevented=false;
  h.form.events.submit({preventDefault(){prevented=true;}});
  assert.equal(prevented,true);assert.notEqual(h.nodes['button[type="submit"]']?.disabled,true);
});

test('valid upload uses native submission and restores the button on history navigation',()=>{
  const h=setup([],{upload:true});h.form.events.submit({preventDefault(){assert.fail('native submission prevented');}});
  assert.equal(h.nodes['button[type="submit"]'].disabled,true);
  assert.match(h.nodes['.form-feedback'].textContent,/upload/i);
  assert.doesNotMatch(h.nodes['.form-feedback'].textContent,/queued|complete/i);
  h.windowEvents.pageshow();assert.equal(h.nodes['button[type="submit"]'].disabled,false);
});

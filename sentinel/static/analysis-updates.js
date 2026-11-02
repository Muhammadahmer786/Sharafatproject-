"use strict";
(() => {
  class UpdatesState {
    constructor(saved) {
      this.records = new Map(); this.initialized = false;
      try {
        const data = JSON.parse(saved);
        this.initialized = data.initialized === true;
        for (const [id, record] of Object.entries(data.records || {}).slice(-100)) {
          if (record && typeof record.revision === 'string') this.records.set(id, {revision:record.revision,read:record.read === true});
        }
      } catch (_) { /* Storage may be unavailable or cleared. */ }
    }
    ingest(items) {
      const alerts = [];
      for (const item of items) {
        const prior = this.records.get(item.id);
        const terminal = ['complete','failed','cancelled','interrupted'].includes(item.state);
        const changed = !prior || prior.revision !== item.revision;
        const record = changed ? {revision:item.revision,read:!terminal} : prior;
        if (changed && terminal && this.initialized) alerts.push(item);
        this.records.delete(item.id); this.records.set(item.id,record);
      }
      while (this.records.size > 100) this.records.delete(this.records.keys().next().value);
      this.initialized = true;
      return alerts;
    }
    unread(item) { const row=this.records.get(item.id); return Boolean(row && row.revision===item.revision && !row.read); }
    markRead(id,revision) { const row=this.records.get(id); if (row?.revision===revision) row.read=true; }
    mergeRead(saved) {
      const other=new UpdatesState(saved);
      for (const [id,row] of this.records) {
        const shared=other.records.get(id);
        if (shared?.revision===row.revision && shared.read) row.read=true;
      }
    }
    serialize() { return JSON.stringify({initialized:this.initialized,records:Object.fromEntries(this.records)}); }
  }
  if (typeof module !== 'undefined' && module.exports) module.exports={UpdatesState};
  if (typeof document === 'undefined') return;
  const root=document.querySelector('[data-analysis-updates]');
  if (!root) return;
  const get=selector=>root.querySelector(selector);
  const toggle=get('[data-updates-toggle]'), panel=get('[data-updates-panel]');
  const list=get('[data-updates-list]'), badge=get('[data-updates-count]');
  const summary=get('[data-updates-summary]'), connection=get('[data-updates-connection]');
  const toast=get('[data-updates-toast]'), toastLink=get('[data-toast-link]');
  const storageKey='sentinel-analysis-updates:'+root.dataset.owner;
  let saved; try {saved=localStorage.getItem(storageKey);} catch (_) {}
  let state=new UpdatesState(saved), items=[], activeCount=0, toastItems=[], rendered='';
  let stopped=false, inFlight=false, timer, controller;
  const persist=()=>{try {state.mergeRead(localStorage.getItem(storageKey));localStorage.setItem(storageKey,state.serialize());} catch (_) {}};
  const safeURL=item=>typeof item.url==='string' && /^\/(?:intelligence|ai)\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(item.url);
  const close=()=>{panel.hidden=true; toggle.setAttribute('aria-expanded','false');};
  function read(rows) { rows.forEach(item=>state.markRead(item.id,item.revision)); persist(); render(); }
  function render() {
    const unread=items.filter(item=>state.unread(item)).length;
    const count=unread || activeCount;
    badge.hidden=!count; badge.textContent=count>99?'99+':String(count);
    badge.dataset.tone=unread?'new':'working';
    toggle.setAttribute('aria-label',`Analysis updates: ${unread} unread, ${activeCount} in progress`);
    summary.textContent=`${activeCount} in progress · ${unread} unread updates`;
    const signature=JSON.stringify(items.map(item=>[item,state.unread(item)]));
    if (signature===rendered) return;
    rendered=signature;
    const focusedId=document.activeElement?.dataset.updateId;
    let restoreFocus;
    list.replaceChildren();
    if (!items.length) {const empty=document.createElement('p');empty.className='updates-empty';empty.textContent='No checks yet. Your analysis updates will appear here.';list.append(empty);}
    for (const item of items) {
      const link=document.createElement('a'); link.href=item.url; link.className='updates-item';
      link.dataset.updateId=item.id;
      if (item.id===focusedId) restoreFocus=link;
      link.dataset.unread=String(state.unread(item));
      const heading=document.createElement('strong'); heading.textContent=item.kind_label+' · '+item.label;
      const target=document.createElement('span'); target.textContent=item.target;
      const status=document.createElement('small'); status.textContent=item.label; status.className='updates-status '+item.tone;
      link.append(heading,target,status); link.addEventListener('click',()=>read([item])); list.append(link);
    }
    restoreFocus?.focus({preventScroll:true});
  }
  function notify(rows) {
    if (!rows.length) return;
    toastItems=rows; toast.hidden=false;
    get('[data-toast-title]').textContent=rows.length===1?rows[0].label:`${rows.length} analysis updates`;
    get('[data-toast-detail]').textContent=rows.length===1?`${rows[0].kind_label} · ${rows[0].target}`:'Your checks have new results or need attention. Open the updates list to review them.';
    toastLink.href=rows.length===1?rows[0].url:'#analysis-updates-panel';
    toastLink.textContent=rows.length===1?'View result →':'View all updates →';
  }
  function updateDetail() {
    const pending=document.querySelector('[data-live-check]');
    if (!pending) return;
    const item=items.find(row=>row.id===pending.dataset.liveCheck);
    if (!item || ['queued','running'].includes(item.state)) return;
    pending.querySelector('h2').textContent=item.label;
    pending.querySelector('p').textContent=item.tone==='ready'
      ? 'Your analysis is complete. Open the result to review the provider findings.'
      : 'This check has an update. Open the result for details and available next steps.';
    const link=pending.querySelector('a'); link.href=item.url; link.textContent='View result →';
    const status=document.querySelector('[data-current-check-badge]');
    if (status) {status.textContent=item.label;status.className='intel-badge '+(item.tone==='ready'?'done':'neutral');}
    pending.removeAttribute('data-live-check');
  }
  function stopForSession() {
    stopped=true;clearTimeout(timer);controller?.abort();items=[];toastItems=[];
    list.replaceChildren();toast.hidden=true;badge.hidden=true;
    summary.textContent='Sign in again to see your updates.';
    connection.hidden=false;connection.textContent='Your session changed or expired. Reload this page to continue.';
  }
  async function poll() {
    if (stopped || inFlight || document.hidden) return;
    clearTimeout(timer);inFlight=true;controller=new AbortController();
    const timeout=setTimeout(()=>controller.abort(),15000);
    try {
      const watches=[];
      if (root.dataset.watch) watches.push('watch='+encodeURIComponent(root.dataset.watch));
      if (root.dataset.watchAi) watches.push('watch_ai='+encodeURIComponent(root.dataset.watchAi));
      const url=root.dataset.feedUrl+(watches.length?'?'+watches.join('&'):'');
      const response=await fetch(url,{headers:{Accept:'application/json'},cache:'no-store',signal:controller.signal});
      if (response.redirected || response.status===401 || response.status===403) {stopForSession();return;}
      if (!response.ok) throw new Error('Updates unavailable');
      const payload=await response.json();
      if (payload.owner!==root.dataset.owner) {stopForSession();return;}
      if (!Array.isArray(payload.items)) throw new Error('Invalid updates');
      items=payload.items.filter(safeURL);activeCount=Number(payload.active_count)||0;
      const alerts=state.ingest(items);persist();render();notify(alerts.filter(item=>state.unread(item)));updateDetail();connection.hidden=true;
    } catch (_) {
      if (!stopped && !document.hidden) {connection.hidden=false;connection.textContent='Connection interrupted. Showing the last known status; retrying automatically.';}
    } finally {
      clearTimeout(timeout);inFlight=false;
      if (!stopped && !document.hidden) timer=setTimeout(poll,10000);
    }
  }
  toggle.addEventListener('click',()=>{const opening=panel.hidden;panel.hidden=!opening;toggle.setAttribute('aria-expanded',String(opening));if(opening)poll();});
  document.addEventListener('click',event=>{if(!root.contains(event.target))close();});
  document.addEventListener('keydown',event=>{if(event.key==='Escape'&&!panel.hidden){close();toggle.focus();}});
  get('[data-updates-read]').addEventListener('click',()=>{read(items);toast.hidden=true;});
  toastLink.addEventListener('click',event=>{
    read(toastItems);
    if (toastItems.length>1) {
      event?.preventDefault();panel.hidden=false;toggle.setAttribute('aria-expanded','true');
      list.children[0]?.focus();toast.hidden=true;
    }
  });
  get('[data-toast-dismiss]').addEventListener('click',()=>{read(toastItems);toast.hidden=true;});
  document.addEventListener('visibilitychange',()=>{clearTimeout(timer);if(document.hidden)controller?.abort();else poll();});
  window.addEventListener('storage',event=>{
    if (event.key!==storageKey || stopped) return;
    state.mergeRead(event.newValue);
    try {
      const latest=localStorage.getItem(storageKey);
      state.mergeRead(latest);
      // Repair a stale concurrent write using its own record set, without ping-ponging snapshots.
      const shared=new UpdatesState(latest);shared.mergeRead(state.serialize());
      const merged=shared.serialize();
      if (merged!==latest) localStorage.setItem(storageKey,merged);
    } catch (_) {}
    render();
  });
  window.addEventListener('pagehide',()=>{clearTimeout(timer);controller?.abort();});
  window.addEventListener('pageshow',()=>{if(!stopped)poll();});
  poll();
})();

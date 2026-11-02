"use strict";
(() => {
  const form=document.querySelector('[data-ai-upload]');
  if (form) {
    const button=form.querySelector('button[type="submit"]');
    const label=button.textContent;
    form.addEventListener('submit',event=>{
      if (typeof validateFileLimits==='function' && !validateFileLimits(form)) {event.preventDefault();return;}
      if (button.disabled) {event.preventDefault();return;}
      button.disabled=true;button.textContent='Uploading…';
      const feedback=form.querySelector('.form-feedback');
      feedback.hidden=false;feedback.textContent='Uploading to your local server. The job page will open after the file is accepted.';
    });
    window.addEventListener('pageshow',()=>{button.disabled=false;button.textContent=label;});
  }
  const root=document.querySelector('[data-ai-job]');
  if (!root || !['queued','running'].includes(root.dataset.state)) return;
  const get=selector=>root.querySelector(selector);
  const stages={queued:['Queued','Waiting for the local worker. One job runs at a time.'],
    inspecting:['Inspecting file','Checking the uploaded binary and preparing static analysis.'],
    decompiling:['Decompiling','Ghidra is extracting code in an isolated worker. The uploaded program is not executed.'],
    analysing:['Analysing evidence','The local model is reviewing a bounded selection of static evidence. This can take several minutes.'],
    validating:['Validating findings','Checking model findings against the evidence supplied to it.'],
    complete:['Analysis complete','Your report is ready. Review the evidence and coverage before drawing a conclusion.'],
    failed:['Analysis failed','No completed assessment is available. Review the error before trying again.'],
    cancelled:['Analysis cancelled','This run was cancelled. It does not establish whether the file is safe.'],
    interrupted:['Analysis interrupted','This run could not finish. Upload the file again to start a new analysis.']};
  const sequence=['queued','inspecting','decompiling','analysing','validating','complete'];
  const terminal=['complete','failed','cancelled','interrupted'];
  let stopped=false,suspended=false,inFlight=false,timer,controller;
  function render(payload) {
    const ended=terminal.includes(payload.state);
    const stage=ended?payload.state:payload.stage;
    const description=stages[stage] || ['Processing','Waiting for the next confirmed worker milestone.'];
    root.dataset.state=payload.state;
    get('[data-ai-stage]').textContent=description[0];
    get('[data-ai-live-message]').textContent=description[1];
    get('[data-ai-state]').textContent=payload.state.charAt(0).toUpperCase()+payload.state.slice(1);
    get('[data-ai-state]').dataset.state=payload.state;
    const bar=get('[data-ai-progress]');
    const milestone=Number(payload.progress);
    if ((!ended || payload.state==='complete') && Number.isFinite(milestone) && milestone>=0 && milestone<=100) {
      bar.setAttribute('aria-valuenow',String(milestone));
      bar.setAttribute('aria-valuetext',description[0]+' · worker milestone');
      get('[data-ai-progress-fill]').style.width=milestone+'%';
      get('[data-ai-milestone]').textContent='Worker milestone · '+milestone+' / 100';
    } else {
      bar.removeAttribute('aria-valuenow');bar.setAttribute('aria-valuetext',description[0]);
      get('[data-ai-milestone]').textContent='No completed assessment';
    }
    const index=sequence.indexOf(stage);
    root.querySelectorAll('[data-ai-step]').forEach(step=>{
      const position=sequence.indexOf(step.dataset.aiStep);
      step.dataset.state=position===index?'current':index>=0 && position<index?'done':'waiting';
      if (position===index) step.setAttribute('aria-current','step');else step.removeAttribute('aria-current');
    });
    const error=get('[data-ai-error]');
    error.textContent=typeof payload.error==='string'?payload.error:'';error.hidden=!error.textContent;
    get('[data-ai-complete]').hidden=payload.state!=='complete';
    get('[data-ai-cancel]').hidden=ended;
    get('[data-ai-terminal-actions]').hidden=!ended;
    // Use the owner-scoped route rendered by the server, never a URL from a status payload.
    get('[data-ai-result-link]').href=root.dataset.resultUrl;
    if (ended) {stopped=true;clearTimeout(timer);}
  }
  function stop(message) {
    stopped=true;clearTimeout(timer);
    get('[data-ai-live-message]').textContent=message;
    get('[data-ai-cancel]').hidden=true;
  }
  async function poll() {
    if (stopped || suspended || inFlight || document.hidden) return;
    clearTimeout(timer);inFlight=true;controller=new AbortController();
    const timeout=setTimeout(()=>controller.abort(),15000);
    try {
      const response=await fetch(root.dataset.statusUrl,{headers:{Accept:'application/json'},cache:'no-store',signal:controller.signal});
      if (suspended || document.hidden) return;
      if (response.redirected || response.status===401 || response.status===403) {stop('Your session changed or expired. Reload this page and sign in to continue.');return;}
      if (response.status===404) {stop('This analysis is no longer available. Return to your local AI history.');return;}
      if (!response.ok) throw new Error('Status unavailable');
      const payload=await response.json();
      if (!payload || payload.id!==root.dataset.aiJob || !['queued','running',...terminal].includes(payload.state)) throw new Error('Invalid status');
      if (!suspended && !document.hidden) render(payload);
    } catch (_) {
      if (!stopped && !suspended && !document.hidden) get('[data-ai-live-message]').textContent='Connection interrupted. Showing the last known status; retrying automatically.';
    } finally {
      clearTimeout(timeout);inFlight=false;
      if (!stopped && !suspended && !document.hidden) timer=setTimeout(poll,3000);
    }
  }
  document.addEventListener('visibilitychange',()=>{clearTimeout(timer);if(document.hidden)controller?.abort();else poll();});
  window.addEventListener('pagehide',()=>{suspended=true;clearTimeout(timer);controller?.abort();});
  window.addEventListener('pageshow',()=>{suspended=false;poll();});
  poll();
})();

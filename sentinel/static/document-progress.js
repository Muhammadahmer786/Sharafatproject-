"use strict";

// Keep native attachment downloads: no blob URLs, extra uploads or stored documents.
(() => {
  const active = new WeakMap();

  function start(form, event) {
    if (active.has(form)) { event.preventDefault(); return true; }
    let token;
    try {
      token = Array.from(crypto.getRandomValues(new Uint8Array(16)), byte => byte.toString(16).padStart(2, '0')).join('');
    } catch (_) { return false; } // Native download and the ordinary notice still work.

    const panel = form.querySelector('[data-progress-panel]');
    const bar = form.querySelector('[data-progress-bar]');
    const status = form.querySelector('[data-progress-status]');
    const detail = form.querySelector('[data-progress-detail]');
    const button = form.querySelector('button[type="submit"]');
    const originalButton = button.innerHTML;
    const protecting = form.dataset.documentProgress === 'protect';
    const cookieName = 'sentinel_download_' + token;
    const started = Date.now();
    form.querySelector('[name="download_token"]').value = token;
    form.querySelector('.form-feedback').hidden = true;
    panel.hidden = false;
    panel.dataset.state = 'working';
    status.textContent = protecting ? 'Protecting your document…' : 'Recovering your document…';
    detail.textContent = protecting
      ? 'Uploading and encrypting your document into the image. Keep this page open.'
      : 'Uploading, decrypting and checking your document. Keep this page open.';
    bar.removeAttribute('aria-valuenow');
    bar.setAttribute('aria-valuetext', status.textContent);
    button.disabled = true;
    button.textContent = protecting ? 'Protecting…' : 'Recovering…';

    function stop(state) {
      clearInterval(active.get(form));
      active.delete(form);
      window.removeEventListener('pagehide', onPageHide);
      button.disabled = false;
      button.innerHTML = originalButton;
      panel.dataset.state = state;
      if (state === 'ready') {
        status.textContent = 'Download started';
        detail.textContent = 'Your file is ready. Check your browser’s Downloads panel or save dialog.';
        bar.setAttribute('aria-valuenow', '100');
        bar.setAttribute('aria-valuetext', 'Processing complete. Download started.');
      } else {
        status.textContent = 'Still waiting for confirmation';
        detail.textContent = 'Check your browser’s Downloads panel. If no file arrives, refresh this page before trying again.';
        bar.removeAttribute('aria-valuenow');
        bar.setAttribute('aria-valuetext', 'Download status is not confirmed.');
      }
    }
    function onPageHide() { stop('waiting'); panel.hidden = true; }
    active.set(form, setInterval(() => {
      const ready = document.cookie.split(';').some(cookie => cookie.trim() === cookieName + '=ready');
      if (ready) {
        document.cookie = cookieName + '=; Max-Age=0; Path=' + location.pathname + '; SameSite=Strict';
        stop('ready');
      } else if (Date.now() - started >= 5 * 60 * 1000) stop('waiting');
    }, 300));
    window.addEventListener('pagehide', onPageHide);
    return true;
  }
  window.SentinelDocumentProgress = {start};
})();

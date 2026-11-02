"use strict";
document.querySelectorAll('[data-key-source]').forEach(form => {
  const update = () => form.querySelectorAll('[data-key-mode]').forEach(group => {
    const active = group.dataset.keyMode === form.querySelector('[name="key_source"]:checked').value;
    group.hidden = !active;
    group.querySelectorAll('input').forEach(input => { input.disabled = !active; });
  });
  form.querySelectorAll('[name="key_source"]').forEach(input => input.addEventListener('change', update));
  update();
});
const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;
const menu = document.getElementById("menu-toggle");
menu?.addEventListener("click", () => {
  const open = document.getElementById("sidebar").classList.toggle("open");
  menu.setAttribute("aria-expanded", String(open));
});
document.addEventListener("click", event => {
  if (innerWidth <= 650 && !event.target.closest(".sidebar, #menu-toggle")) {
    document.getElementById("sidebar")?.classList.remove("open");
    menu?.setAttribute("aria-expanded", "false");
  }
});
document.addEventListener("keydown", event => {
  if (event.key === "/" && !event.target.matches("input,textarea,select") && innerWidth > 1200) {
    const search = document.querySelector(".top-search input");
    if (search) { event.preventDefault(); search.focus(); }
  }
});
document.querySelectorAll("[data-toggle-password]").forEach(button => button.addEventListener("click", () => {
  const input = document.getElementById(button.dataset.togglePassword);
  const show = input.type === "password";
  input.type = show ? "text" : "password";
  button.textContent = show ? "Hide" : "Show";
  button.setAttribute("aria-label", show ? "Hide password" : "Show password");
}));
document.querySelectorAll("[data-dropzone]").forEach(zone => {
  const input = zone.querySelector("input");
  input.addEventListener("change", () => {
    const file = input.files[0];
    if (file) {
      zone.querySelector(".file-label strong").textContent = file.name;
      zone.querySelector(".file-label span").textContent = (file.size/1024).toFixed(1) + " KB · Click to replace";
    }
  });
  for (const type of ["dragenter","dragover"]) zone.addEventListener(type, e => {e.preventDefault(); zone.classList.add("dragover");});
  for (const type of ["dragleave","drop"]) zone.addEventListener(type, () => zone.classList.remove("dragover"));
  zone.addEventListener("drop", e => {
    e.preventDefault();
    if (e.dataTransfer.files.length) {
      const transfer = new DataTransfer(); transfer.items.add(e.dataTransfer.files[0]);
      input.files = transfer.files; input.dispatchEvent(new Event("change", {bubbles:true}));
    }
  });
});
const capacityNote = document.getElementById("capacity-note");
let capacityController;
if (capacityNote) document.getElementById("image").addEventListener("change", async event => {
  const file = event.target.files[0];
  if (!file) return;
  capacityController?.abort(); capacityController = new AbortController();
  if (file.size > Number(event.target.dataset.maxBytes)) { capacityNote.textContent = "This image exceeds the 22 MiB limit."; return; }
  capacityNote.textContent = "Checking image capacity…";
  const data = new FormData(); data.append("image",file);
  try {
    const response = await fetch("/image-capacity",{method:"POST",body:data,headers:{"X-CSRFToken":csrfToken},signal:capacityController.signal});
    const result = await response.json();
    capacityNote.textContent = response.ok ? result.width+" × "+result.height+" pixels · about "+(result.estimated_document_bytes/1024).toFixed(0)+" KB for a document. Exact capacity is checked before encryption." : result.error || "Could not check capacity.";
  } catch(error) {
    if (error.name !== "AbortError") capacityNote.textContent = "Capacity will be checked when you submit.";
  }
});
function validateFileLimits(form) {
  let error = '';
  let total = 0;
  const readable = bytes => bytes >= 1024*1024 ? `${bytes/(1024*1024)} MiB` : `${bytes/1024} KiB`;
  form.querySelectorAll('input[type="file"]').forEach(input => {
    const file = input.files[0];
    const limit = Number(input.dataset.maxBytes);
    const message = !input.disabled && file && limit && file.size > limit
      ? `${input.getAttribute('aria-label') || 'File'} must be ${readable(limit)} or smaller. Choose a smaller file.` : '';
    input.setCustomValidity(message);
    if (message) { input.setAttribute('aria-invalid','true'); error ||= message; }
    else input.removeAttribute('aria-invalid');
    if (!input.disabled && file) total += file.size;
  });
  const requestLimit = Number(form.dataset.maxRequestBytes);
  if (!error && total > requestLimit) error = `The selected files exceed the ${readable(requestLimit)} combined upload limit. Choose smaller files.`;
  const feedback = form.querySelector('.form-feedback');
  feedback.className = error ? 'form-feedback error' : 'form-feedback';
  feedback.textContent = error;
  feedback.hidden = !error;
  return !error;
}
document.querySelectorAll('[data-max-request-bytes]').forEach(form => form.addEventListener('change', event => {
  if (event.target.type === 'file' || event.target.name === 'key_source') validateFileLimits(form);
}));
document.querySelectorAll("[data-download-form]").forEach(form => form.addEventListener("submit", event => {
  if (form.hasAttribute('data-max-request-bytes') && !validateFileLimits(form)) {
    event.preventDefault();
    return;
  }
  if (form.hasAttribute('data-document-progress') && window.SentinelDocumentProgress) {
    if (window.SentinelDocumentProgress.start(form, event)) return;
  }
  // Native attachment responses also work in browsers that cannot save blob URLs.
  // Do not disable the form: attachment responses leave the current page open.
  const feedback = form.querySelector(".form-feedback");
  feedback.className="form-feedback";
  feedback.textContent=event.submitter?.value === "view"
    ? "Verifying your identity and preparing your encrypted private key…"
    : "Your download will start automatically when processing finishes. Check your browser’s Downloads panel for the file. Any validation error will appear on this page.";
  feedback.hidden=false;
}));
document.querySelectorAll("[data-processing-form]").forEach(form => form.addEventListener("submit", () => {
  const button=form.querySelector('button[type="submit"]'); button.disabled=true; button.textContent=button.dataset.busyText || "Processing…";
}));
document.querySelectorAll("[data-confirm]").forEach(form => form.addEventListener("submit",event => {
  if (!confirm(form.dataset.confirm)) event.preventDefault();
}));
document.querySelectorAll("[data-copy]").forEach(button => button.addEventListener("click",async () => {
  try {await navigator.clipboard.writeText(button.dataset.copy); button.textContent="✓"; button.setAttribute("aria-label","Copied");}
  catch (_) {button.setAttribute("aria-label","Select the hash and copy it manually");}
}));
document.querySelectorAll('[data-copy-target]').forEach(button => button.addEventListener('click', async () => {
  const field = document.getElementById(button.dataset.copyTarget);
  if (!field?.value) return;
  try {
    await navigator.clipboard.writeText(field.value);
    button.textContent = 'Copied';
  } catch (_) {
    field.focus(); field.select();
    button.textContent = 'Selected — copy manually';
  }
}));
const privateKeyView = document.querySelector('[data-private-key-view]');
if (privateKeyView) {
  const clearPrivateKey = () => {
    const field = privateKeyView.querySelector('textarea');
    field.value = ''; field.defaultValue = ''; field.textContent = '';
    privateKeyView.hidden = true;
    document.querySelector('[data-private-key-locked]').hidden = false;
  };
  window.addEventListener('pagehide', clearPrivateKey);
  setTimeout(clearPrivateKey, 5 * 60 * 1000);
}
const pending=document.querySelector("[data-poll-url]");
if (pending) {
  let attempts=0;
  const timer=setInterval(async () => {
    if (++attempts>45) {clearInterval(timer);return;}
    try {
      const response=await fetch(pending.dataset.pollUrl);
      if (response.ok && (await response.json()).status!=="pending") {clearInterval(timer);location.reload();}
    } catch (_) { /* Retain pending status until there is a real result. */ }
  },3000);
}

import { createShare } from './shareApi.js';

let modalEl = null;

function ensureModal() {
  if (modalEl) return modalEl;
  modalEl = document.createElement('div');
  modalEl.className = 'modal-overlay hidden';
  modalEl.innerHTML = `
    <div class="modal-box" role="dialog" aria-modal="true">
      <button class="modal-close" type="button" aria-label="Close">✕</button>
      <div class="modal-content"></div>
    </div>`;
  modalEl.addEventListener('click', (e) => {
    if (e.target === modalEl) closeModal();
  });
  modalEl.querySelector('.modal-close').addEventListener('click', closeModal);
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !modalEl.classList.contains('hidden')) closeModal();
  });
  document.body.appendChild(modalEl);
  return modalEl;
}

function closeModal() {
  if (modalEl) modalEl.classList.add('hidden');
}

function labelFor(type) {
  return type === 'compare' ? 'comparison' : 'analysis';
}

function renderConsentStep(content, { type, buildPayload }) {
  content.innerHTML = `
    <h3 class="modal-title">Share this ${labelFor(type)}</h3>
    <p class="modal-text">
      This stores the ${labelFor(type)} <b>encrypted</b> in a database for <b>24 hours</b> so you can share a link
      with colleagues. It expires automatically and <b>cannot be extended</b> — after 24 hours it's gone for good.
      Nothing is shared until you agree below.
    </p>
    <label class="consent-row">
      <input type="checkbox" id="shareConsentCheckbox" />
      <span>I consent to this ${labelFor(type)} being stored encrypted in a database for 24 hours.</span>
    </label>
    <div class="error-banner hidden" id="shareModalError"></div>
    <div class="btn-row" style="margin-top:18px;">
      <button class="btn btn-primary" id="shareConfirmBtn" type="button" disabled>Create share link</button>
      <button class="btn btn-ghost" id="shareCancelBtn" type="button">Cancel</button>
    </div>
  `;
  const checkbox = content.querySelector('#shareConsentCheckbox');
  const confirmBtn = content.querySelector('#shareConfirmBtn');
  const errorEl = content.querySelector('#shareModalError');

  checkbox.addEventListener('change', () => {
    confirmBtn.disabled = !checkbox.checked;
  });
  content.querySelector('#shareCancelBtn').addEventListener('click', closeModal);

  confirmBtn.addEventListener('click', async () => {
    confirmBtn.disabled = true;
    confirmBtn.textContent = 'Creating…';
    errorEl.classList.add('hidden');
    try {
      const payload = buildPayload();
      const result = await createShare(type, payload);
      renderResultStep(content, type, result);
    } catch (e) {
      errorEl.textContent = e.message || 'Something went wrong creating the share link.';
      errorEl.classList.remove('hidden');
      confirmBtn.disabled = false;
      confirmBtn.textContent = 'Create share link';
    }
  });
}

function renderResultStep(content, type, { id, password, expiresAt, url: serverUrl }) {
  const url = serverUrl || `${location.origin}/s/${id}`;
  const expiresDate = new Date(expiresAt);
  content.innerHTML = `
    <h3 class="modal-title">Share link created</h3>
    <p class="modal-text">
      Send the link and the password to your colleague — ideally over separate channels. This expires
      <b>${expiresDate.toLocaleString()}</b> and cannot be renewed.
    </p>
    <label class="share-field-label">Link</label>
    <div class="share-copy-row">
      <input type="text" readonly value="${url}" id="shareUrlInput" />
      <button class="btn btn-ghost btn-sm" type="button" data-copy-target="shareUrlInput">Copy</button>
    </div>
    <label class="share-field-label">One-time password</label>
    <div class="share-copy-row">
      <input type="text" readonly value="${password}" id="sharePasswordInput" />
      <button class="btn btn-ghost btn-sm" type="button" data-copy-target="sharePasswordInput">Copy</button>
    </div>
    <div class="btn-row" style="margin-top:18px;">
      <button class="btn btn-primary" id="shareDoneBtn" type="button">Done</button>
    </div>
  `;
  content.querySelectorAll('[data-copy-target]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const input = content.querySelector('#' + btn.dataset.copyTarget);
      input.select();
      const done = () => {
        btn.textContent = 'Copied!';
        setTimeout(() => {
          btn.textContent = 'Copy';
        }, 1500);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(input.value).then(done, () => document.execCommand('copy') && done());
      } else {
        document.execCommand('copy');
        done();
      }
    });
  });
  content.querySelector('#shareDoneBtn').addEventListener('click', closeModal);
}

export function openShareModal({ type, buildPayload }) {
  const modal = ensureModal();
  modal.classList.remove('hidden');
  const content = modal.querySelector('.modal-content');
  renderConsentStep(content, { type, buildPayload });
}

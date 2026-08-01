import { fetchShareStatus, unlockShare } from './shareApi.js';
import { renderSummary, renderOverview, renderHops, renderHeaderTable, renderAuthAccordion, renderSpamPanel } from './renderAnalysis.js';
import { renderVerdictCompare, buildHeaderDiff, renderDiffTable } from './renderCompare.js';

const els = {
  unlockPanel: document.getElementById('unlockPanel'),
  passwordInput: document.getElementById('passwordInput'),
  unlockBtn: document.getElementById('unlockBtn'),
  statusLine: document.getElementById('statusLine'),
  statusText: document.getElementById('statusText'),
  errorBanner: document.getElementById('errorBanner'),
  expiryBanner: document.getElementById('expiryBanner'),

  analysisResults: document.getElementById('analysisResults'),
  summaryGrid: document.getElementById('summaryGrid'),
  overviewTable: document.getElementById('overviewTable'),
  hopList: document.getElementById('hopList'),
  hopCount: document.getElementById('hopCount'),
  authAccordion: document.getElementById('authAccordion'),
  spamPanel: document.getElementById('spamPanel'),
  spamAccordion: document.getElementById('spamAccordion'),
  headerViewTabs: document.getElementById('headerViewTabs'),
  headerSearch: document.getElementById('headerSearch'),
  headerTable: document.getElementById('headerTable'),
  toggleRawBtn: document.getElementById('toggleRawBtn'),
  rawSource: document.getElementById('rawSource'),
  spfOverrideDisabled: true, // read-only share view — no live recheck

  compareResultsView: document.getElementById('compareResultsView'),
  verdictCompareTable: document.getElementById('verdictCompareTable'),
  hopListA: document.getElementById('hopListA'),
  hopCountA: document.getElementById('hopCountA'),
  hopListB: document.getElementById('hopListB'),
  hopCountB: document.getElementById('hopCountB'),
  diffTable: document.getElementById('diffTable'),
  diffSearch: document.getElementById('diffSearch'),
  onlyDiffToggle: document.getElementById('onlyDiffToggle'),
};

const hopElsA = { hopList: els.hopListA, hopCount: els.hopCountA };
const hopElsB = { hopList: els.hopListB, hopCount: els.hopCountB };

let compareDiffRows = [];
let headerViewState = 'other';

init();

function getShareId() {
  const parts = location.pathname.split('/').filter(Boolean);
  return parts[parts.length - 1];
}

async function init() {
  const yearEl = document.getElementById('currentYear');
  if (yearEl) yearEl.textContent = new Date().getFullYear();

  const id = getShareId();
  if (!id) {
    showFatalError('No share ID found in this URL.');
    return;
  }

  try {
    await fetchShareStatus(id);
  } catch (e) {
    showFatalError(e.message);
    return;
  }

  els.unlockBtn.addEventListener('click', () => attemptUnlock(id));
  els.passwordInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') attemptUnlock(id);
  });
  els.passwordInput.focus();

  els.headerViewTabs.addEventListener('click', (e) => {
    const btn = e.target.closest('.tab-btn');
    if (!btn) return;
    headerViewState = btn.dataset.view;
    els.headerViewTabs.querySelectorAll('.tab-btn').forEach((b) => b.classList.toggle('active', b === btn));
    renderHeaderTable(els, lastHeaders, els.headerSearch.value, headerViewState);
  });
  els.headerSearch.addEventListener('input', () => renderHeaderTable(els, lastHeaders, els.headerSearch.value, headerViewState));
  els.toggleRawBtn.addEventListener('click', () => {
    const hidden = els.rawSource.classList.toggle('hidden');
    els.toggleRawBtn.textContent = hidden ? 'Show raw source' : 'Hide raw source';
  });

  const accordionToggleHandler = (e) => {
    const header = e.target.closest('.accordion-header');
    if (header) header.closest('.accordion-item').classList.toggle('open');
  };
  els.authAccordion.addEventListener('click', accordionToggleHandler);
  els.spamAccordion.addEventListener('click', accordionToggleHandler);

  els.diffSearch.addEventListener('input', () => renderDiffTable(els, compareDiffRows, els.diffSearch.value, els.onlyDiffToggle.checked));
  els.onlyDiffToggle.addEventListener('change', () => renderDiffTable(els, compareDiffRows, els.diffSearch.value, els.onlyDiffToggle.checked));
}

let lastHeaders = [];

function setStatus(text) {
  if (text === null) {
    els.statusLine.classList.add('hidden');
    return;
  }
  els.statusLine.classList.remove('hidden');
  els.statusText.textContent = text;
}

function showError(message) {
  els.errorBanner.innerHTML = `
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 8v5M12 16h.01"/></svg>
    <span>${message}</span>`;
  els.errorBanner.classList.remove('hidden');
}

function showFatalError(message) {
  showError(message);
  els.passwordInput.disabled = true;
  els.unlockBtn.disabled = true;
}

async function attemptUnlock(id) {
  const password = els.passwordInput.value.trim();
  if (!password) return;
  els.unlockBtn.disabled = true;
  setStatus('Unlocking…');
  els.errorBanner.classList.add('hidden');
  try {
    const { type, payload, expiresAt } = await unlockShare(id, password);
    els.unlockPanel.classList.add('hidden');
    showExpiryBanner(expiresAt);
    if (type === 'compare') {
      renderCompareView(payload);
    } else {
      renderAnalysisView(payload);
    }
  } catch (e) {
    showError(e.message);
  } finally {
    setStatus(null);
    els.unlockBtn.disabled = false;
  }
}

function showExpiryBanner(expiresAt) {
  const date = new Date(expiresAt);
  els.expiryBanner.innerHTML = `
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display:inline;vertical-align:-2px;margin-right:6px;"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/></svg>
    This share expires <b>${date.toLocaleString()}</b> and cannot be renewed.`;
  els.expiryBanner.classList.remove('hidden');
}

function renderAnalysisView(data) {
  els.analysisResults.classList.remove('hidden');
  lastHeaders = data.headers || [];

  renderOverview(els, data.headers, data.note);
  renderHops(els, data.hops || []);
  headerViewState = 'other';
  els.headerViewTabs.querySelectorAll('.tab-btn').forEach((b) => b.classList.toggle('active', b.dataset.view === 'other'));
  renderHeaderTable(els, data.headers, '', headerViewState);
  els.rawSource.textContent = (data.headerBlock || '') + (data.body ? '\n\n' + data.body : '');
  renderSpamPanel(els, data.spamResults || []);
  renderSummary(els, data.spf, data.dkimResults, data.dmarc, data.alignment);
  renderAuthAccordion(els, data.spf, data.dkimResults, data.dmarc, data.alignment, data.authResultsReported || [], data.fromDomain, data.bimi);
}

function renderCompareView(data) {
  els.compareResultsView.classList.remove('hidden');
  compareDiffRows = data.diffRows || buildHeaderDiff(data.a.headers, data.b.headers);
  renderVerdictCompare(els, data.a, data.b);
  renderHops(hopElsA, data.a.hops || []);
  renderHops(hopElsB, data.b.hops || []);
  renderDiffTable(els, compareDiffRows, '', els.onlyDiffToggle.checked);
}

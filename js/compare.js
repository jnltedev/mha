import { splitHeadersAndBody, parseHeaders, getFirstHeader, extractEmailAddress, domainFromEmail } from './headerParser.js';
import { parseReceivedChain, guessOriginatingIP } from './receivedChain.js';
import { checkSPF } from './spf.js';
import { checkDKIMSignatures } from './dkim.js';
import { checkDMARC, evaluateDMARCAlignment } from './dmarc.js';
import { parseEML, parseMSG } from './fileParsers.js';
import { renderVerdictCompare, buildHeaderDiff, renderDiffTable, escapeHTML } from './renderCompare.js';
import { renderHops } from './renderAnalysis.js';
import { openShareModal } from './shareModal.js';

const els = {
  inputA: document.getElementById('inputA'),
  inputB: document.getElementById('inputB'),
  fileA: document.getElementById('fileA'),
  fileB: document.getElementById('fileB'),
  tabsA: document.getElementById('tabsA'),
  tabsB: document.getElementById('tabsB'),
  dropzoneA: document.getElementById('dropzoneA'),
  dropzoneB: document.getElementById('dropzoneB'),
  filenameChipA: document.getElementById('filenameChipA'),
  filenameChipB: document.getElementById('filenameChipB'),
  filenameTextA: document.getElementById('filenameTextA'),
  filenameTextB: document.getElementById('filenameTextB'),
  clearFileBtnA: document.getElementById('clearFileBtnA'),
  clearFileBtnB: document.getElementById('clearFileBtnB'),
  compareBtn: document.getElementById('compareBtn'),
  clearCompareBtn: document.getElementById('clearCompareBtn'),
  statusLine: document.getElementById('statusLine'),
  statusText: document.getElementById('statusText'),
  errorBanner: document.getElementById('errorBanner'),
  compareResults: document.getElementById('compareResults'),
  verdictCompareTable: document.getElementById('verdictCompareTable'),
  hopListA: document.getElementById('hopListA'),
  hopCountA: document.getElementById('hopCountA'),
  hopListB: document.getElementById('hopListB'),
  hopCountB: document.getElementById('hopCountB'),
  diffTable: document.getElementById('diffTable'),
  diffSearch: document.getElementById('diffSearch'),
  onlyDiffToggle: document.getElementById('onlyDiffToggle'),
  shareBtn: document.getElementById('shareBtn'),
};

const hopElsA = { hopList: els.hopListA, hopCount: els.hopCountA };
const hopElsB = { hopList: els.hopListB, hopCount: els.hopCountB };

const state = { fileA: null, fileB: null, modeA: 'upload', modeB: 'upload', diffRows: [] };
let currentCompare = null;

init();

function init() {
  const yearEl = document.getElementById('currentYear');
  if (yearEl) yearEl.textContent = new Date().getFullYear();

  setupSide('A');
  setupSide('B');

  els.compareBtn.addEventListener('click', () => compare());
  els.clearCompareBtn.addEventListener('click', () => {
    els.inputA.value = '';
    els.inputB.value = '';
    clearFile('A');
    clearFile('B');
    els.compareResults.classList.add('hidden');
    hideError();
  });
  els.diffSearch.addEventListener('input', () => renderDiffTable(els, state.diffRows, els.diffSearch.value, els.onlyDiffToggle.checked));
  els.onlyDiffToggle.addEventListener('change', () => renderDiffTable(els, state.diffRows, els.diffSearch.value, els.onlyDiffToggle.checked));

  if (els.shareBtn) {
    els.shareBtn.addEventListener('click', () => {
      if (!currentCompare) return;
      openShareModal({
        type: 'compare',
        buildPayload: () => currentCompare,
      });
    });
  }
}

function setupSide(slot) {
  const tabsEl = els[`tabs${slot}`];
  const section = tabsEl.closest('.compare-col');
  tabsEl.querySelectorAll('.tab-btn').forEach((btn) => {
    btn.addEventListener('click', () => switchSideTab(slot, btn.dataset.tab, section, tabsEl));
  });

  const dropzone = els[`dropzone${slot}`];
  const fileInput = els[`file${slot}`];
  dropzone.addEventListener('click', () => fileInput.click());
  dropzone.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') fileInput.click();
  });
  dropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropzone.classList.add('dragover');
  });
  dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
  dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.classList.remove('dragover');
    if (e.dataTransfer.files && e.dataTransfer.files[0]) setFile(slot, e.dataTransfer.files[0]);
  });
  fileInput.addEventListener('change', () => {
    if (fileInput.files && fileInput.files[0]) setFile(slot, fileInput.files[0]);
  });
  els[`clearFileBtn${slot}`].addEventListener('click', (e) => {
    e.stopPropagation();
    clearFile(slot);
  });
}

function switchSideTab(slot, tab, section, tabsEl) {
  state[`mode${slot}`] = tab;
  tabsEl.querySelectorAll('.tab-btn').forEach((b) => b.classList.toggle('active', b.dataset.tab === tab));
  section.querySelectorAll('.tab-panel').forEach((p) => p.classList.toggle('active', p.dataset.tabPanel === tab));
}

function setFile(slot, file) {
  state[`file${slot}`] = file;
  els[`filenameText${slot}`].textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
  els[`filenameChip${slot}`].classList.add('show');
}

function clearFile(slot) {
  state[`file${slot}`] = null;
  els[`file${slot}`].value = '';
  els[`filenameChip${slot}`].classList.remove('show');
}

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

function hideError() {
  els.errorBanner.classList.add('hidden');
  els.errorBanner.innerHTML = '';
}

async function loadSide(slot) {
  if (state[`mode${slot}`] === 'upload') {
    const file = state[`file${slot}`];
    if (!file) return null;
    const name = file.name.toLowerCase();
    if (name.endsWith('.msg')) {
      const buf = await file.arrayBuffer();
      const parsed = await parseMSG(buf);
      return { headerBlock: parsed.headerBlock, body: parsed.body };
    }
    const text = await file.text();
    return parseEML(text);
  }
  const raw = els[`input${slot}`].value;
  if (!raw || !raw.trim()) return null;
  return splitHeadersAndBody(raw);
}

async function analyzeSide(headerBlock, body) {
  const headers = parseHeaders(headerBlock);
  const hops = parseReceivedChain(headers);

  let ip = null, domain = null;
  const receivedSpf = getFirstHeader(headers, 'received-spf');
  if (receivedSpf) {
    const ipMatch = receivedSpf.unfolded.match(/client-ip=([0-9a-fA-F.:]+)/i);
    const domMatch = receivedSpf.unfolded.match(/(?:envelope-from|smtp\.mailfrom)=["']?([^;\s"']+)/i);
    if (ipMatch) ip = ipMatch[1];
    if (domMatch) domain = domainFromEmail(domMatch[1]);
  }
  if (!ip) {
    const guess = guessOriginatingIP(hops);
    if (guess) ip = guess.ip;
  }
  if (!domain) {
    const returnPath = getFirstHeader(headers, 'return-path');
    const addr = returnPath ? extractEmailAddress(returnPath.unfolded) : null;
    domain = addr ? domainFromEmail(addr) : null;
  }
  if (!domain) {
    const from = getFirstHeader(headers, 'from');
    const addr = from ? extractEmailAddress(from.unfolded) : null;
    domain = addr ? domainFromEmail(addr) : null;
  }

  const fromHeader = getFirstHeader(headers, 'from');
  const fromAddr = fromHeader ? extractEmailAddress(fromHeader.unfolded) : null;
  const fromDomain = domainFromEmail(fromAddr);

  const spf = await checkSPF(domain, ip);
  const dkimResults = await checkDKIMSignatures(headers, body);
  const dmarc = await checkDMARC(fromDomain);
  const alignment = dmarc.result === 'found'
    ? evaluateDMARCAlignment({ dmarcTags: dmarc.tags, fromDomain, spfResult: spf.result, spfDomain: spf.domain, dkimResults })
    : null;

  return { headers, hops, spf, dkimResults, dmarc, alignment, fromDomain };
}

async function compare() {
  els.compareBtn.disabled = true;
  hideError();
  try {
    const [rawA, rawB] = await Promise.all([loadSide('A'), loadSide('B')]);
    if (!rawA || !rawA.headerBlock.trim()) {
      showError('Message A is empty — paste headers or upload a file for message A.');
      return;
    }
    if (!rawB || !rawB.headerBlock.trim()) {
      showError('Message B is empty — paste headers or upload a file for message B.');
      return;
    }

    setStatus('Checking message A (SPF / DKIM / DMARC)…');
    const a = await analyzeSide(rawA.headerBlock, rawA.body);
    setStatus('Checking message B (SPF / DKIM / DMARC)…');
    const b = await analyzeSide(rawB.headerBlock, rawB.body);

    els.compareResults.classList.remove('hidden');
    renderVerdictCompare(els, a, b);
    renderHops(hopElsA, a.hops);
    renderHops(hopElsB, b.hops);
    state.diffRows = buildHeaderDiff(a.headers, b.headers);
    renderDiffTable(els, state.diffRows, els.diffSearch.value, els.onlyDiffToggle.checked);
    currentCompare = { a, b, diffRows: state.diffRows };
  } catch (e) {
    console.error(e);
    showError(`Something went wrong while comparing: <b>${escapeHTML(e.message)}</b>.`);
  } finally {
    setStatus(null);
    els.compareBtn.disabled = false;
  }
}


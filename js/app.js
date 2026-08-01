import {
  splitHeadersAndBody,
  parseHeaders,
  getFirstHeader,
  extractEmailAddress,
  domainFromEmail,
} from './headerParser.js';
import { parseReceivedChain, guessOriginatingIP } from './receivedChain.js';
import { checkSPF } from './spf.js';
import { checkDKIMSignatures } from './dkim.js';
import { checkDMARC, evaluateDMARCAlignment } from './dmarc.js';
import { parseAuthenticationResults } from './authResults.js';
import { parseEML, parseMSG } from './fileParsers.js';
import { SAMPLE_HEADER } from './sample.js';
import { parseSpamHeaders } from './spamHeaders.js';
import { checkBIMI } from './bimi.js';
import {
  renderSummary,
  renderOverview,
  renderHops,
  renderHeaderTable,
  renderAuthAccordion,
  renderSpamPanel,
  escapeHTML,
} from './renderAnalysis.js';
import { openShareModal } from './shareModal.js';

const els = {
  tabBtns: document.querySelectorAll('#input-panel .tab-btn'),
  tabPanels: document.querySelectorAll('.tab-panel'),
  headerViewTabs: document.getElementById('headerViewTabs'),
  pasteInput: document.getElementById('pasteInput'),
  dropzone: document.getElementById('dropzone'),
  fileInput: document.getElementById('fileInput'),
  filenameChip: document.getElementById('filenameChip'),
  filenameText: document.getElementById('filenameText'),
  clearFileBtn: document.getElementById('clearFileBtn'),
  analyzeBtn: document.getElementById('analyzeBtn'),
  sampleBtn: document.getElementById('sampleBtn'),
  clearBtn: document.getElementById('clearBtn'),
  statusLine: document.getElementById('statusLine'),
  statusText: document.getElementById('statusText'),
  results: document.getElementById('results'),
  featureStrip: document.getElementById('featureStrip'),
  summaryGrid: document.getElementById('summaryGrid'),
  overviewTable: document.getElementById('overviewTable'),
  hopList: document.getElementById('hopList'),
  hopCount: document.getElementById('hopCount'),
  authAccordion: document.getElementById('authAccordion'),
  spamPanel: document.getElementById('spamPanel'),
  spamAccordion: document.getElementById('spamAccordion'),
  headerSearch: document.getElementById('headerSearch'),
  headerTable: document.getElementById('headerTable'),
  toggleRawBtn: document.getElementById('toggleRawBtn'),
  rawSource: document.getElementById('rawSource'),
  errorBanner: document.getElementById('errorBanner'),
  shareBtn: document.getElementById('shareBtn'),
};

const state = {
  activeTab: 'upload',
  file: null,
  lastHeaders: [],
  headerView: 'other',
};

init();

function init() {
  const yearEl = document.getElementById('currentYear');
  if (yearEl) yearEl.textContent = new Date().getFullYear();

  els.tabBtns.forEach((btn) => btn.addEventListener('click', () => switchTab(btn.dataset.tab)));

  els.dropzone.addEventListener('click', () => els.fileInput.click());
  els.dropzone.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') els.fileInput.click();
  });
  els.dropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    els.dropzone.classList.add('dragover');
  });
  els.dropzone.addEventListener('dragleave', () => els.dropzone.classList.remove('dragover'));
  els.dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    els.dropzone.classList.remove('dragover');
    if (e.dataTransfer.files && e.dataTransfer.files[0]) setFile(e.dataTransfer.files[0]);
  });
  els.fileInput.addEventListener('change', () => {
    if (els.fileInput.files && els.fileInput.files[0]) setFile(els.fileInput.files[0]);
  });
  els.clearFileBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    clearFile();
  });

  els.analyzeBtn.addEventListener('click', () => analyze());
  els.sampleBtn.addEventListener('click', () => {
    switchTab('paste');
    els.pasteInput.value = SAMPLE_HEADER;
    els.pasteInput.focus();
  });
  els.clearBtn.addEventListener('click', () => {
    els.pasteInput.value = '';
    clearFile();
    els.results.classList.add('hidden');
    els.featureStrip.classList.remove('hidden');
    hideError();
  });

  els.headerSearch.addEventListener('input', () => renderHeaderTable(els, state.lastHeaders, els.headerSearch.value, state.headerView));
  els.headerViewTabs.addEventListener('click', (e) => {
    const btn = e.target.closest('.tab-btn');
    if (!btn) return;
    state.headerView = btn.dataset.view;
    els.headerViewTabs.querySelectorAll('.tab-btn').forEach((b) => b.classList.toggle('active', b === btn));
    renderHeaderTable(els, state.lastHeaders, els.headerSearch.value, state.headerView);
  });
  els.toggleRawBtn.addEventListener('click', () => {
    const hidden = els.rawSource.classList.toggle('hidden');
    els.toggleRawBtn.textContent = hidden ? 'Show raw source' : 'Hide raw source';
  });

  const accordionToggleHandler = (e) => {
    const header = e.target.closest('.accordion-header');
    if (header) {
      header.closest('.accordion-item').classList.toggle('open');
      return;
    }
    const recheckBtn = e.target.closest('[data-recheck-spf]');
    if (recheckBtn) recheckSPF();
  };
  els.authAccordion.addEventListener('click', accordionToggleHandler);
  els.spamAccordion.addEventListener('click', accordionToggleHandler);

  if (els.shareBtn) {
    els.shareBtn.addEventListener('click', () => {
      if (!currentAnalysis) return;
      openShareModal({
        type: 'analysis',
        buildPayload: () => currentAnalysis,
      });
    });
  }
}

function switchTab(tab) {
  state.activeTab = tab;
  els.tabBtns.forEach((b) => b.classList.toggle('active', b.dataset.tab === tab));
  els.tabPanels.forEach((p) => p.classList.toggle('active', p.dataset.tabPanel === tab));
}

function setFile(file) {
  state.file = file;
  els.filenameText.textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
  els.filenameChip.classList.add('show');
}

function clearFile() {
  state.file = null;
  els.fileInput.value = '';
  els.filenameChip.classList.remove('show');
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

async function analyze() {
  els.analyzeBtn.disabled = true;
  hideError();
  try {
    let headerBlock, body, note = null;

    if (state.activeTab === 'upload') {
      if (!state.file) {
        showError('Please choose an .eml or .msg file first, or switch to the "Paste headers" tab.');
        return;
      }
      setStatus('Reading file…');
      const name = state.file.name.toLowerCase();
      if (name.endsWith('.msg')) {
        const buf = await state.file.arrayBuffer();
        setStatus('Parsing .msg file…');
        const parsed = await parseMSG(buf);
        headerBlock = parsed.headerBlock;
        body = parsed.body;
        note = parsed.note;
      } else {
        const text = await state.file.text();
        const parsed = parseEML(text);
        headerBlock = parsed.headerBlock;
        body = parsed.body;
      }
    } else {
      const raw = els.pasteInput.value;
      if (!raw || !raw.trim()) {
        showError('Paste some headers first, or switch to the "Upload .eml / .msg" tab.');
        return;
      }
      const parsed = splitHeadersAndBody(raw);
      headerBlock = parsed.headerBlock;
      body = parsed.body;
    }

    if (!headerBlock || !headerBlock.trim()) {
      showError(
        'No headers could be found in this input. Make sure it starts with header lines like "From:" or "Received:" — ' +
          'if you pasted only part of an email, include the full header block from the top of the message.'
      );
      return;
    }

    const headers = parseHeaders(headerBlock);
    state.lastHeaders = headers;

    await runAnalysis(headers, body, headerBlock, note);
  } catch (e) {
    console.error(e);
    showError(
      `Something went wrong while analyzing this message: <b>${escapeHTML(e.message)}</b>. ` +
        'This usually means the input wasn\'t a valid header block/EML file, or a DNS lookup failed — check the browser console for details and try again.'
    );
  } finally {
    setStatus(null);
    els.analyzeBtn.disabled = false;
  }
}

let currentAnalysis = null;

async function runAnalysis(headers, body, headerBlock, note) {
  els.results.classList.remove('hidden');
  els.featureStrip.classList.add('hidden');

  const hops = parseReceivedChain(headers);
  renderOverview(els, headers, note);
  renderHops(els, hops);
  els.headerSearch.value = '';
  state.headerView = 'other';
  els.headerViewTabs.querySelectorAll('.tab-btn').forEach((b) => b.classList.toggle('active', b.dataset.view === 'other'));
  renderHeaderTable(els, headers, '', state.headerView);
  els.rawSource.textContent = headerBlock + (body ? '\n\n' + body : '');

  const spfInputs = determineSPFInputs(headers, hops);
  const fromHeader = getFirstHeader(headers, 'from');
  const fromAddr = fromHeader ? extractEmailAddress(fromHeader.unfolded) : null;
  const fromDomain = domainFromEmail(fromAddr);

  const authResultsReported = parseAuthenticationResults(headers);

  setStatus('Checking SPF…');
  const spf = await checkSPF(spfInputs.domain, spfInputs.ip);
  spf.ipSource = spfInputs.ipSource;
  spf.domainSource = spfInputs.domainSource;

  setStatus('Verifying DKIM signature(s)…');
  const dkimResults = await checkDKIMSignatures(headers, body);

  setStatus('Checking DMARC…');
  const dmarc = await checkDMARC(fromDomain);
  const alignment = dmarc.result === 'found'
    ? evaluateDMARCAlignment({ dmarcTags: dmarc.tags, fromDomain, spfResult: spf.result, spfDomain: spf.domain, dkimResults })
    : null;

  setStatus('Checking BIMI…');
  const bimi = await checkBIMI(fromDomain);

  const spamResults = parseSpamHeaders(headers);
  renderSpamPanel(els, spamResults);

  currentAnalysis = {
    headers, hops, note, body, spf, dkimResults, dmarc, alignment, fromDomain, bimi,
    spamResults, authResultsReported, headerBlock,
  };

  renderSummary(els, spf, dkimResults, dmarc, alignment);
  renderAuthAccordion(els, spf, dkimResults, dmarc, alignment, authResultsReported, fromDomain, bimi);

  if (els.shareBtn) els.shareBtn.classList.remove('hidden');
}

async function recheckSPF() {
  const ipInput = document.getElementById('spfIpOverride');
  const domainInput = document.getElementById('spfDomainOverride');
  if (!ipInput || !domainInput || !currentAnalysis) return;
  setStatus('Rechecking SPF…');
  els.statusLine.classList.remove('hidden');
  const spf = await checkSPF(domainInput.value.trim(), ipInput.value.trim());
  spf.ipSource = 'manual override';
  spf.domainSource = 'manual override';
  currentAnalysis.spf = spf;

  const dmarc = currentAnalysis.dmarc;
  const alignment = dmarc.result === 'found'
    ? evaluateDMARCAlignment({
        dmarcTags: dmarc.tags,
        fromDomain: currentAnalysis.fromDomain,
        spfResult: spf.result,
        spfDomain: spf.domain,
        dkimResults: currentAnalysis.dkimResults,
      })
    : null;
  currentAnalysis.alignment = alignment;

  renderSummary(els, spf, currentAnalysis.dkimResults, dmarc, alignment);
  renderAuthAccordion(els, spf, currentAnalysis.dkimResults, dmarc, alignment, parseAuthenticationResults(currentAnalysis.headers), currentAnalysis.fromDomain, currentAnalysis.bimi);
  setStatus(null);
}

// ---------- SPF input heuristics ----------

function determineSPFInputs(headers, hops) {
  let ip = null, ipSource = null, domain = null, domainSource = null;

  const receivedSpf = getFirstHeader(headers, 'received-spf');
  if (receivedSpf) {
    const ipMatch = receivedSpf.unfolded.match(/client-ip=([0-9a-fA-F.:]+)/i);
    const domMatch = receivedSpf.unfolded.match(/(?:envelope-from|smtp\.mailfrom)=["']?([^;\s"']+)/i);
    if (ipMatch) { ip = ipMatch[1]; ipSource = 'Received-SPF header'; }
    if (domMatch) { domain = domainFromEmail(domMatch[1]); domainSource = 'Received-SPF header'; }
  }

  if (!ip) {
    const guess = guessOriginatingIP(hops);
    if (guess) { ip = guess.ip; ipSource = `Received header, hop #${guess.hop.index + 1}`; }
  }

  if (!domain) {
    const returnPath = getFirstHeader(headers, 'return-path');
    if (returnPath) {
      const addr = extractEmailAddress(returnPath.unfolded);
      if (addr) { domain = domainFromEmail(addr); domainSource = 'Return-Path header'; }
    }
  }
  if (!domain) {
    const from = getFirstHeader(headers, 'from');
    if (from) {
      const addr = extractEmailAddress(from.unfolded);
      if (addr) { domain = domainFromEmail(addr); domainSource = 'From header'; }
    }
  }

  return { ip, ipSource, domain, domainSource };
}

import { decodeMimeWords } from './mimeWords.js';
import { getOrgDomain } from './dmarc.js';
import { getHeader } from './headerParser.js';
import { lookupCountry } from './geoip.js';
import { isPrivateIP, isLocalTransferProtocol } from './receivedChain.js';

export const PROMINENT_HEADERS = new Set([
  'from', 'to', 'cc', 'bcc', 'reply-to', 'subject', 'date', 'message-id',
  'return-path', 'received', 'received-spf', 'dkim-signature', 'authentication-results',
]);

export function escapeHTML(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function badgeClass(result) {
  if (result === 'pass') return 'badge-pass';
  if (result === 'fail') return 'badge-fail';
  if (result === 'none' || result === 'neutral') return 'badge-none';
  return 'badge-warn';
}

export function verdictClass(result) {
  if (result === 'pass') return 'v-pass';
  if (result === 'fail') return 'v-fail';
  if (result === 'none') return 'v-none';
  return 'v-warn';
}

export const ICONS = {
  spf: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z"/><path d="M9 12l2 2 4-4"/></svg>',
  dkim: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="15" r="4"/><path d="M11 12l8-8M16 5l3 3M19 5l2 2"/></svg>',
  dmarc: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6 9-6"/></svg>',
  overall: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M9 12l2 2 4-4"/></svg>',
};

export const CHEVRON_SVG = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M9 6l6 6-6 6"/></svg>';

export function summarizeDKIM(results) {
  if (!results.length) return { result: 'none', explanation: 'No DKIM-Signature header present in this message.' };
  const passing = results.filter((r) => r.result === 'pass');
  if (passing.length) return { result: 'pass', explanation: `${passing.length}/${results.length} signature(s) cryptographically verified.` };
  if (results.some((r) => r.result === 'fail')) return { result: 'fail', explanation: 'At least one DKIM signature failed verification.' };
  if (results.every((r) => r.result === 'unverified')) return { result: 'unverified', explanation: 'Public key found in DNS, but the message body was not available to fully verify (paste headers only, or upload the .eml).' };
  return { result: results[0].result, explanation: results[0].explanation };
}

export function overallVerdict(spf, dkimSummary, dmarc, alignment) {
  if (dmarc.result === 'found' && alignment) {
    if (alignment.pass) return { result: 'pass', explanation: 'DMARC alignment passes — the message is authenticated for this domain.' };
    const policy = (dmarc.tags.p || 'none').toLowerCase();
    return {
      result: policy === 'none' ? 'warn' : 'fail',
      explanation: `DMARC alignment fails. Domain policy is p=${policy}${policy === 'reject' ? ' — receivers should reject this message.' : policy === 'quarantine' ? ' — receivers should quarantine (spam) this message.' : ' — no enforcement requested, but the message is not properly authenticated.'}`,
    };
  }
  if (spf.result === 'pass' || dkimSummary.result === 'pass') {
    return { result: 'warn', explanation: 'SPF or DKIM passes individually, but no DMARC policy was found to confirm alignment with the From domain.' };
  }
  return { result: 'fail', explanation: 'Neither SPF nor DKIM passed, and no DMARC policy was found.' };
}

export function kvRow(label, value) {
  if (!value) return '';
  return `<tr><td>${escapeHTML(label)}</td><td>${escapeHTML(value)}</td></tr>`;
}

export function accordionItem(title, badgeResult, bodyHtml, open = false) {
  return `
  <div class="accordion-item${open ? ' open' : ''}">
    <div class="accordion-header">
      <div class="accordion-header-left">
        <span class="accordion-title">${title}</span>
        ${badgeResult ? `<span class="badge ${badgeClass(badgeResult)}">${escapeHTML(badgeResult)}</span>` : ''}
      </div>
      <span class="accordion-chevron">${CHEVRON_SVG}</span>
    </div>
    <div class="accordion-body">${bodyHtml}</div>
  </div>`;
}

export function formatLocalDate(date) {
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    timeZoneName: 'short',
  });
}

export function extractResolvedName(detail) {
  if (!detail) return null;
  const m = detail.match(/^\(([^[]+?)\s*\[/);
  return m ? m[1].trim() : null;
}

export function renderSummary(els, spf, dkimResults, dmarc, alignment) {
  const dkimSummary = summarizeDKIM(dkimResults);
  const dmarcBadgeResult = dmarc.result === 'found' ? (alignment && alignment.pass ? 'pass' : 'fail') : 'none';
  const overall = overallVerdict(spf, dkimSummary, dmarc, alignment);

  const cards = [
    { label: 'SPF', icon: ICONS.spf, result: spf.result, detail: `<b>${escapeHTML(spf.domain || '—')}</b> · ${escapeHTML(spf.explanation || '')}` },
    { label: 'DKIM', icon: ICONS.dkim, result: dkimSummary.result, detail: escapeHTML(dkimSummary.explanation) },
    { label: 'DMARC', icon: ICONS.dmarc, result: dmarcBadgeResult, detail: dmarc.result === 'found' ? `policy <b>p=${escapeHTML(dmarc.tags.p || 'none')}</b> · ${alignment && alignment.pass ? 'aligned' : 'not aligned'}` : escapeHTML(dmarc.explanation || 'No DMARC record found') },
    { label: 'Overall', icon: ICONS.overall, result: overall.result === 'warn' ? 'neutral' : overall.result, detail: escapeHTML(overall.explanation) },
  ];

  els.summaryGrid.innerHTML = cards
    .map(
      (c) => `
      <div class="verdict-card ${verdictClass(c.result)}">
        <div class="verdict-top">
          <div class="verdict-label-row">
            <span class="verdict-icon">${c.icon}</span>
            <span class="verdict-label">${c.label}</span>
          </div>
          <span class="badge ${badgeClass(c.result)}">${escapeHTML(c.result)}</span>
        </div>
        <div class="verdict-detail">${c.detail}</div>
      </div>`
    )
    .join('');
}

export function renderOverview(els, headers, note) {
  const get = (name) => {
    const h = getHeader(headers, name);
    return h ? h.unfolded : null;
  };
  let html = '';
  if (note) html += `<tr><td colspan="2"><div class="note-banner">${escapeHTML(note)}</div></td></tr>`;
  html += kvRow('From', decodeMimeWords(get('from')));
  html += kvRow('To', decodeMimeWords(get('to')));
  html += kvRow('Cc', decodeMimeWords(get('cc')));
  html += kvRow('Reply-To', decodeMimeWords(get('reply-to')));
  html += kvRow('Subject', decodeMimeWords(get('subject')));
  html += kvRow('Date', get('date'));
  html += kvRow('Message-ID', get('message-id'));
  html += kvRow('Return-Path', get('return-path'));
  els.overviewTable.innerHTML = html || '<tr><td>—</td><td>No standard headers found</td></tr>';
}

export function renderHops(els, hops) {
  els.hopCount.textContent = hops.length;
  if (!hops.length) {
    els.hopList.innerHTML = '<p style="color:var(--text-dim);font-size:13px;">No Received headers found.</p>';
    return;
  }
  els.hopList.innerHTML = hops
    .map((hop) => {
      const resolved = extractResolvedName(hop.fromDetail);
      const mismatch = resolved && hop.fromHost && resolved.toLowerCase() !== hop.fromHost.toLowerCase();

      const route = hop.fromHost
        ? `<span class="hop-host">${escapeHTML(hop.fromHost)}</span>${hop.by ? `<svg class="hop-arrow" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M13 6l6 6-6 6"/></svg><span class="hop-host hop-host-to">${escapeHTML(hop.by)}</span>` : ''}`
        : `<span class="hop-route-empty">no explicit sender — internal hop${hop.by ? ` (delivered by ${escapeHTML(hop.by)})` : ''}</span>`;

      const chips = [];
      if (hop.ip) chips.push(`<span class="hop-chip mono" data-ip-chip="${escapeHTML(hop.ip)}"><span class="hop-flag" data-ip-flag></span>${escapeHTML(hop.ip)}</span>`);
      if (mismatch) chips.push(`<span class="hop-chip ${resolved.toLowerCase() === 'unknown' ? 'hop-chip-warn' : ''}">reverse DNS: ${escapeHTML(resolved)}</span>`);
      const isInternalHop = isLocalTransferProtocol(hop.protocol) || (hop.ip && isPrivateIP(hop.ip));
      if (hop.tlsVersion) {
        chips.push(`<span class="hop-chip hop-chip-ok">🔒 ${escapeHTML(hop.tlsVersion)}</span>`);
      } else if (hop.ip && !isInternalHop) {
        chips.push(`<span class="hop-chip hop-chip-warn">⚠ no TLS info in header</span>`);
      }
      if (hop.date) chips.push(`<span class="hop-chip">${escapeHTML(formatLocalDate(new Date(hop.date)))}</span>`);

      return `
      <div class="hop">
        <div class="hop-marker">
          <div class="hop-dot">${hop.index + 1}</div>
          <div class="hop-line"></div>
        </div>
        <div class="hop-card">
          <div class="hop-card-top">
            <span class="hop-idx">Hop ${hop.index + 1}</span>
            ${hop.delaySeconds !== null ? `<span class="hop-delay">+${hop.delaySeconds}s</span>` : ''}
          </div>
          <div class="hop-route">${route}</div>
          <div class="hop-chips">${chips.join('')}</div>
        </div>
      </div>`;
    })
    .join('');

  enhanceHopFlags(els, hops);
}

export function enhanceHopFlags(els, hops) {
  const uniqueIPs = [...new Set(hops.map((h) => h.ip).filter(Boolean))];
  uniqueIPs.forEach((ip) => {
    const setFlag = (flag, title) => {
      els.hopList.querySelectorAll(`[data-ip-chip="${CSS.escape(ip)}"] [data-ip-flag]`).forEach((el) => {
        el.textContent = flag + ' ';
        el.title = title;
      });
    };

    if (isPrivateIP(ip)) {
      setFlag('🏳️', 'Private/internal IP — no public geolocation');
      return;
    }

    lookupCountry(ip).then((info) => {
      if (info && info.flag) {
        setFlag(info.flag, info.name);
      } else {
        setFlag('🏳️', 'Country could not be determined for this IP');
      }
    });
  });
}

export function renderHeaderTable(els, headers, filter, headerView) {
  const f = (filter || '').toLowerCase();
  let rows = headers;
  if (headerView === 'other') {
    rows = rows.filter((h) => !PROMINENT_HEADERS.has(h.name.toLowerCase()));
  }
  rows = rows.filter((h) => !f || h.name.toLowerCase().includes(f) || h.unfolded.toLowerCase().includes(f));
  const emptyMessage = headerView === 'other'
    ? 'No other headers — everything in this message is already shown above. Switch to "All headers" to see the full list.'
    : 'No matching headers';
  els.headerTable.innerHTML = rows
    .map((h) => `<tr><td class="hname">${escapeHTML(h.name)}</td><td class="hvalue">${escapeHTML(h.unfolded)}</td></tr>`)
    .join('') || `<tr><td colspan="2" style="color:var(--text-dim);">${escapeHTML(emptyMessage)}</td></tr>`;
}

export function renderAuthAccordion(els, spf, dkimResults, dmarc, alignment, authResultsReported, fromDomain, bimi) {
  let html = '';

  // SPF
  const spfTrace = (spf.trace || [])
    .map((t) => (t.note ? `<li>${escapeHTML(t.note)}</li>` : `<li><b>${escapeHTML(t.domain)}</b>: ${escapeHTML(t.record || '(no SPF record)')}</li>`))
    .join('');
  const spfDomainDiffersFromFrom =
    spf.domain && fromDomain && getOrgDomain(spf.domain) !== getOrgDomain(fromDomain);
  const spfNote = spfDomainDiffersFromFrom
    ? `<div class="note-banner">SPF is checked against the envelope sender (Return-Path: <b>${escapeHTML(spf.domain)}</b>), not the visible From address (<b>${escapeHTML(fromDomain)}</b>) — that's how SPF is defined (RFC 7208). They differ here because the message passed through a forwarding service that rewrote the envelope sender (commonly SRS). This is checked separately from DMARC alignment below.</div>`
    : '';
  const spfBody = `
    ${spfNote}
    <table class="kv">
      ${kvRow('Checked domain', `${spf.domain || '—'} ${spf.domainSource ? `(source: ${spf.domainSource})` : ''}`)}
      ${kvRow('Checked IP', `${spf.ip || '—'} ${spf.ipSource ? `(source: ${spf.ipSource})` : ''}`)}
      ${kvRow('Result', spf.explanation)}
    </table>
    ${spfTrace ? `<ul class="trace-list">${spfTrace}</ul>` : ''}
    ${els.spfOverrideDisabled ? '' : `
    <div class="override-row">
      <input type="text" id="spfIpOverride" placeholder="Override IP" value="${escapeHTML(spf.ip || '')}" />
      <input type="text" id="spfDomainOverride" placeholder="Override domain" value="${escapeHTML(spf.domain || '')}" />
      <button class="btn btn-ghost btn-sm" data-recheck-spf type="button">Recheck</button>
    </div>`}
  `;
  html += accordionItem('SPF (Sender Policy Framework)', spf.result, spfBody, true);

  // DKIM
  let dkimBody = '';
  if (!dkimResults.length) {
    dkimBody = '<p style="color:var(--text-dim);font-size:13px;">No DKIM-Signature header found in this message.</p>';
  } else {
    dkimBody = dkimResults
      .map(
        (d, i) => `
      <div style="padding:10px 0;${i > 0 ? 'border-top:1px solid var(--border-soft);' : ''}">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
          <b style="font-size:13px;">Signature ${i + 1} — d=${escapeHTML(d.domain || '?')} s=${escapeHTML(d.selector || '?')}</b>
          <span class="badge ${badgeClass(d.result)}">${escapeHTML(d.result)}</span>
        </div>
        <table class="kv">
          ${kvRow('Algorithm', d.algo)}
          ${kvRow('Canonicalization', `${d.headerCanon}/${d.bodyCanon}`)}
          ${kvRow('Signed headers', d.tags && d.tags.h)}
          ${kvRow('Explanation', d.explanation)}
        </table>
      </div>`
      )
      .join('');
  }
  const dkimSummary = summarizeDKIM(dkimResults);
  html += accordionItem('DKIM (DomainKeys Identified Mail)', dkimSummary.result, dkimBody);

  // DMARC
  let dmarcBody = '';
  if (dmarc.result === 'found') {
    dmarcBody = `
      <table class="kv">
        ${kvRow('Policy domain', dmarc.domain + (dmarc.subdomainPolicy ? ' (organizational domain policy)' : ''))}
        ${kvRow('Policy (p=)', dmarc.tags.p || 'none')}
        ${kvRow('Subdomain policy (sp=)', dmarc.tags.sp || '(same as p=)')}
        ${kvRow('Percentage (pct=)', dmarc.tags.pct || '100')}
        ${kvRow('SPF alignment (aspf=)', alignment.aspf === 's' ? 'strict' : 'relaxed')}
        ${kvRow('DKIM alignment (adkim=)', alignment.adkim === 's' ? 'strict' : 'relaxed')}
        ${kvRow('SPF aligned', alignment.spfAligned ? 'yes' : 'no')}
        ${kvRow('DKIM aligned', alignment.dkimAligned ? 'yes' : 'no')}
        ${kvRow('Raw record', dmarc.record)}
      </table>`;
  } else {
    dmarcBody = `<p style="color:var(--text-dim);font-size:13px;">${escapeHTML(dmarc.explanation || 'No DMARC record found for ' + fromDomain)}</p>`;
  }
  const dmarcBadgeResult = dmarc.result === 'found' ? (alignment && alignment.pass ? 'pass' : 'fail') : 'none';
  html += accordionItem('DMARC (Domain-based Message Authentication)', dmarcBadgeResult, dmarcBody);

  // BIMI
  if (bimi) {
    let bimiBody = '';
    let bimiBadge = 'none';
    if (bimi.result === 'found') {
      bimiBadge = 'pass';
      const notEnforced = !dmarc.tags || !['quarantine', 'reject'].includes((dmarc.tags.p || 'none').toLowerCase());
      bimiBody = `
        ${notEnforced ? `<div class="note-banner">This domain publishes a BIMI record, but its DMARC policy is not enforced (p=${escapeHTML((dmarc.tags && dmarc.tags.p) || 'none')}). Most mailbox providers only display the BIMI logo when DMARC is enforced (p=quarantine or p=reject).</div>` : ''}
        ${bimi.logoUrl ? `<div style="margin-bottom:12px;"><img src="${escapeHTML(bimi.logoUrl)}" alt="BIMI logo" style="max-height:64px;max-width:200px;background:#fff;border-radius:8px;padding:8px;" onerror="this.style.display='none'" /></div>` : ''}
        <table class="kv">
          ${kvRow('Selector', `${bimi.selector}._bimi.${bimi.domain}`)}
          ${kvRow('Logo URL (l=)', bimi.logoUrl || '—')}
          ${kvRow('Authority evidence (a=)', bimi.authorityUrl || '(none — no Verified Mark Certificate)')}
          ${kvRow('Raw record', bimi.record)}
        </table>`;
    } else {
      bimiBody = `<p style="color:var(--text-dim);font-size:13px;">${escapeHTML(bimi.explanation || 'No BIMI record found.')}</p>`;
    }
    html += accordionItem('BIMI (Brand Indicators for Message Identification)', bimiBadge, bimiBody);
  }

  // Reported Authentication-Results
  if (authResultsReported.length) {
    const arBody = authResultsReported
      .map(
        (ar) => `
      <div style="padding:8px 0;">
        <div style="font-size:12.5px;color:var(--text-dim);margin-bottom:4px;">Reported by <b style="color:var(--text);">${escapeHTML(ar.authserv)}</b></div>
        <div style="font-family:var(--mono);font-size:12px;color:var(--text-dim);background:var(--bg);border:1px solid var(--border-soft);border-radius:7px;padding:8px 10px;word-break:break-all;">${escapeHTML(ar.raw)}</div>
      </div>`
      )
      .join('');
    html += accordionItem(`Authentication-Results reported by receiving server(s) (${authResultsReported.length})`, null, arBody);
  }

  els.authAccordion.innerHTML = html;
}

export function renderSpamPanel(els, spamResults) {
  if (!spamResults.length) {
    els.spamPanel.classList.add('hidden');
    els.spamAccordion.innerHTML = '';
    return;
  }
  els.spamPanel.classList.remove('hidden');

  const html = spamResults
    .map((r) => {
      const symbolsList = r.symbols.length
        ? `<ul class="trace-list">${r.symbols
            .map(
              (s) =>
                `<li><b>${escapeHTML(s.name)}</b>${s.score !== null ? ` (${s.score > 0 ? '+' : ''}${s.score})` : ''}${s.detail ? ` — ${escapeHTML(s.detail)}` : ''}</li>`
            )
            .join('')}</ul>`
        : '';
      const body = `
        <table class="kv">
          ${kvRow('Source header', r.header)}
          ${kvRow('Summary', r.summary)}
        </table>
        ${symbolsList}
      `;
      return accordionItem(`${r.engine}`, r.tone, body);
    })
    .join('');

  els.spamAccordion.innerHTML = html;
}

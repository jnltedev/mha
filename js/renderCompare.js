import { decodeMimeWords } from './mimeWords.js';

export function escapeHTML(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function badgeClass(result) {
  if (result === 'pass') return 'badge-pass';
  if (result === 'fail') return 'badge-fail';
  if (result === 'none' || result === 'neutral') return 'badge-none';
  return 'badge-warn';
}

export function summarizeDKIM(results) {
  if (!results.length) return 'none';
  if (results.some((r) => r.result === 'pass')) return 'pass';
  if (results.some((r) => r.result === 'fail')) return 'fail';
  if (results.every((r) => r.result === 'unverified')) return 'unverified';
  return results[0].result;
}

function badge(result) {
  return `<span class="badge ${badgeClass(result)}">${escapeHTML(result)}</span>`;
}

export function renderVerdictCompare(els, a, b) {
  const dmarcResultOf = (x) => (x.dmarc.result === 'found' ? (x.alignment && x.alignment.pass ? 'pass' : 'fail') : 'none');

  const rows = [
    { label: 'SPF', a: a.spf.result, b: b.spf.result, detailA: a.spf.domain, detailB: b.spf.domain },
    { label: 'DKIM', a: summarizeDKIM(a.dkimResults), b: summarizeDKIM(b.dkimResults) },
    { label: 'DMARC', a: dmarcResultOf(a), b: dmarcResultOf(b), detailA: a.dmarc.tags && `p=${a.dmarc.tags.p}`, detailB: b.dmarc.tags && `p=${b.dmarc.tags.p}` },
  ];

  const headRow = `<tr><th>Check</th><th>Message A</th><th>Message B</th><th></th></tr>`;
  const bodyRows = rows
    .map((r) => {
      const differs = r.a !== r.b;
      return `<tr>
        <td>${r.label}</td>
        <td>${badge(r.a)}${r.detailA ? ` <span class="mono" style="color:var(--text-faint);font-size:11px;">${escapeHTML(r.detailA)}</span>` : ''}</td>
        <td>${badge(r.b)}${r.detailB ? ` <span class="mono" style="color:var(--text-faint);font-size:11px;">${escapeHTML(r.detailB)}</span>` : ''}</td>
        <td>${differs ? '<span class="diff-flag">differs</span>' : ''}</td>
      </tr>`;
    })
    .join('');

  els.verdictCompareTable.innerHTML = headRow + bodyRows;
}

export function buildHeaderDiff(headersA, headersB) {
  const groupByName = (headers) => {
    const map = {};
    headers.forEach((h) => {
      const key = h.name.toLowerCase();
      if (!map[key]) map[key] = { name: h.name, values: [] };
      map[key].values.push(decodeMimeWords(h.unfolded));
    });
    return map;
  };

  const byA = groupByName(headersA);
  const byB = groupByName(headersB);
  const allKeys = Array.from(new Set([...Object.keys(byA), ...Object.keys(byB)])).sort();

  const rows = [];
  for (const key of allKeys) {
    const entryA = byA[key];
    const entryB = byB[key];
    const name = (entryA || entryB).name;
    const count = Math.max(entryA ? entryA.values.length : 0, entryB ? entryB.values.length : 0);
    for (let i = 0; i < count; i++) {
      const a = entryA && entryA.values[i] !== undefined ? entryA.values[i] : null;
      const b = entryB && entryB.values[i] !== undefined ? entryB.values[i] : null;
      rows.push({
        name: count > 1 ? `${name} #${i + 1}` : name,
        a,
        b,
        changed: a !== b,
      });
    }
  }
  return rows;
}

export function renderDiffTable(els, diffRows, filter, onlyDiff) {
  const f = (filter || '').toLowerCase();

  let rows = diffRows;
  if (onlyDiff) rows = rows.filter((r) => r.changed);
  if (f) {
    rows = rows.filter(
      (r) =>
        r.name.toLowerCase().includes(f) ||
        (r.a && r.a.toLowerCase().includes(f)) ||
        (r.b && r.b.toLowerCase().includes(f))
    );
  }

  els.diffTable.innerHTML =
    rows
      .map(
        (r) => `<tr class="${r.changed ? 'diff-changed' : 'diff-same'}">
      <td class="diff-name">${escapeHTML(r.name)}</td>
      <td class="diff-value-a">${r.a !== null ? escapeHTML(r.a) : '<span style="color:var(--text-faint);font-style:italic;">— not present —</span>'}</td>
      <td class="diff-value-b">${r.b !== null ? escapeHTML(r.b) : '<span style="color:var(--text-faint);font-style:italic;">— not present —</span>'}</td>
    </tr>`
      )
      .join('') ||
    `<tr><td colspan="3" style="color:var(--text-dim);padding:14px 10px;">No headers match${onlyDiff ? ' (or nothing differs between the two messages)' : ''}.</td></tr>`;
}

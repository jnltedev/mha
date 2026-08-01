const SCL_LABELS = [
  { max: -1, label: 'Trusted / bypassed filtering', tone: 'pass' },
  { max: 0, label: 'Not spam (SCL 0)', tone: 'pass' },
  { max: 1, label: 'Not spam (SCL 1)', tone: 'pass' },
  { max: 4, label: 'Possibly spam', tone: 'warn' },
  { max: 6, label: 'Spam', tone: 'fail' },
  { max: 9, label: 'High-confidence spam', tone: 'fail' },
];

function get(headers, name) {
  const n = name.toLowerCase();
  return headers.find((h) => h.name.toLowerCase() === n) || null;
}

function sclLabel(scl) {
  const n = Number(scl);
  if (Number.isNaN(n)) return { label: `SCL ${scl}`, tone: 'neutral' };
  const match = SCL_LABELS.find((l) => n <= l.max) || SCL_LABELS[SCL_LABELS.length - 1];
  return { label: match.label, tone: match.tone };
}

function parseRspamd(header) {
  const value = header.unfolded;
  const head = value.match(/^([^:]+):\s*(True|False)\s*\[\s*([-\d.]+)\s*\/\s*([-\d.]+)\s*\]/i);
  if (!head) return null;
  const isSpam = head[2].toLowerCase() === 'true';
  const score = parseFloat(head[3]);
  const threshold = parseFloat(head[4]);

  const symbols = [];
  const symbolRegex = /([A-Z0-9_]+)\(([-\d.]+)\)(\[[^\]]*\])?/g;
  let m;
  while ((m = symbolRegex.exec(value)) !== null) {
    symbols.push({ name: m[1], score: parseFloat(m[2]), detail: m[3] ? m[3].slice(1, -1) : null });
  }
  symbols.sort((a, b) => b.score - a.score);

  return {
    engine: 'Rspamd',
    header: header.name,
    tone: isSpam ? 'fail' : 'pass',
    summary: `${isSpam ? 'Flagged as spam' : 'Not flagged as spam'} — score ${score} / ${threshold}`,
    score,
    threshold,
    symbols,
    raw: value,
  };
}

function parseSpamAssassin(header) {
  const value = header.unfolded;
  const head = value.match(/^(Yes|No)\s*,\s*score=([-\d.]+)\s*required=([-\d.]+)/i);
  if (!head) return null;
  const isSpam = head[1].toLowerCase() === 'yes';
  const score = parseFloat(head[2]);
  const required = parseFloat(head[3]);
  const testsMatch = value.match(/tests=([^\s]+)/i);
  const tests = testsMatch ? testsMatch[1].split(',').filter(Boolean) : [];
  const autolearnMatch = value.match(/autolearn=(\w+)/i);

  return {
    engine: 'SpamAssassin',
    header: header.name,
    tone: isSpam ? 'fail' : 'pass',
    summary: `${isSpam ? 'Flagged as spam' : 'Not flagged as spam'} — score ${score} / ${required}${autolearnMatch ? ` · autolearn=${autolearnMatch[1]}` : ''}`,
    score,
    threshold: required,
    symbols: tests.map((t) => ({ name: t, score: null, detail: null })),
    raw: value,
  };
}

function parseMicrosoft(headers) {
  const sclHeader = get(headers, 'x-ms-exchange-organization-scl') || get(headers, 'x-microsoft-antispam-mailbox-delivery');
  const forefront = get(headers, 'x-forefront-antispam-report');

  let scl = null;
  let sourceHeader = null;
  if (sclHeader) {
    const m = sclHeader.unfolded.match(/-?\d+/);
    if (m) {
      scl = m[0];
      sourceHeader = sclHeader.name;
    }
  }
  if (scl === null && forefront) {
    const m = forefront.unfolded.match(/SCL:(-?\d+)/i);
    if (m) {
      scl = m[1];
      sourceHeader = forefront.name;
    }
  }
  if (scl === null) return null;

  const { label, tone } = sclLabel(scl);
  const pcl = forefront ? forefront.unfolded.match(/PCL:(-?\d+)/i) : null;

  return {
    engine: 'Microsoft 365 Defender',
    header: sourceHeader,
    tone,
    summary: `${label} (SCL ${scl})${pcl ? ` · Phishing Confidence Level ${pcl[1]}` : ''}`,
    score: Number(scl),
    threshold: null,
    symbols: [],
    raw: (sclHeader || forefront).unfolded,
  };
}

function parseGenericFlag(headers) {
  const flag = get(headers, 'x-spam-flag');
  const scoreHeader = get(headers, 'x-spam-score') || get(headers, 'x-spam-level');
  if (!flag && !scoreHeader) return null;

  const isSpam = flag ? /^yes$/i.test(flag.unfolded.trim()) : null;
  const scoreText = scoreHeader ? scoreHeader.unfolded.trim() : null;

  return {
    engine: 'Generic spam filter',
    header: (flag || scoreHeader).name,
    tone: isSpam === null ? 'neutral' : isSpam ? 'fail' : 'pass',
    summary: [flag ? `X-Spam-Flag: ${flag.unfolded.trim()}` : null, scoreText ? `score ${scoreText}` : null].filter(Boolean).join(' · '),
    score: null,
    threshold: null,
    symbols: [],
    raw: [flag && flag.unfolded, scoreHeader && scoreHeader.unfolded].filter(Boolean).join(' / '),
  };
}

export function parseSpamHeaders(headers) {
  const results = [];

  const rspamdHeader = get(headers, 'x-spamd-result') || get(headers, 'x-rspamd-result');
  if (rspamdHeader) {
    const r = parseRspamd(rspamdHeader);
    if (r) results.push(r);
  }

  const saHeader = get(headers, 'x-spam-status');
  if (saHeader) {
    const r = parseSpamAssassin(saHeader);
    if (r) results.push(r);
  }

  const ms = parseMicrosoft(headers);
  if (ms) results.push(ms);

  const generic = parseGenericFlag(headers);
  if (generic) results.push(generic);

  return results;
}

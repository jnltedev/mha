import { queryTXT } from './dns.js';

export async function checkDMARC(fromDomain) {
  if (!fromDomain) return { result: 'none', explanation: 'No From-domain available to check.' };

  const org = getOrgDomain(fromDomain);
  try {
    let record = await lookupRecord(`_dmarc.${fromDomain}`);
    let usedDomain = fromDomain;
    let subdomainPolicy = false;

    if (!record && org !== fromDomain) {
      record = await lookupRecord(`_dmarc.${org}`);
      usedDomain = org;
      subdomainPolicy = true;
    }

    if (!record) {
      return { result: 'none', explanation: `No DMARC record found at _dmarc.${fromDomain}`, domain: fromDomain };
    }

    const tags = parseTags(record);
    return { result: 'found', record, tags, domain: usedDomain, subdomainPolicy, fromDomain };
  } catch (e) {
    return { result: 'error', explanation: e.message };
  }
}

async function lookupRecord(name) {
  const res = await queryTXT(name);
  return (res.records || []).find((r) => /^v=DMARC1/i.test(r)) || null;
}

function parseTags(record) {
  const tags = {};
  record.split(';').forEach((part) => {
    const idx = part.indexOf('=');
    if (idx === -1) return;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (k) tags[k] = v;
  });
  return tags;
}

const TWO_PART_TLDS = new Set(['co.uk', 'com.au', 'co.jp', 'com.br', 'co.nz', 'co.in', 'com.mx', 'co.za', 'org.uk', 'net.au']);

// Best-effort registrable-domain heuristic (not a full public-suffix-list implementation).
export function getOrgDomain(domain) {
  if (!domain) return domain;
  const parts = domain.toLowerCase().split('.');
  if (parts.length <= 2) return domain.toLowerCase();
  const lastTwo = parts.slice(-2).join('.');
  if (TWO_PART_TLDS.has(lastTwo) && parts.length > 2) return parts.slice(-3).join('.');
  return lastTwo;
}

export function evaluateDMARCAlignment({ dmarcTags, fromDomain, spfResult, spfDomain, dkimResults }) {
  const adkim = (dmarcTags.adkim || 'r').toLowerCase();
  const aspf = (dmarcTags.aspf || 'r').toLowerCase();

  const spfAligned = spfResult === 'pass' && domainsAlign(fromDomain, spfDomain, aspf);
  const passingDkim = (dkimResults || []).filter((d) => d.result === 'pass');
  const dkimAligned = passingDkim.some((d) => domainsAlign(fromDomain, d.domain, adkim));

  return {
    pass: spfAligned || dkimAligned,
    spfAligned,
    dkimAligned,
    adkim,
    aspf,
  };
}

function domainsAlign(a, b, mode) {
  if (!a || !b) return false;
  a = a.toLowerCase();
  b = b.toLowerCase();
  if (mode === 's') return a === b;
  return getOrgDomain(a) === getOrgDomain(b);
}

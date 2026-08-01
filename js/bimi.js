import { queryTXT } from './dns.js';

function parseTagList(value) {
  const tags = {};
  value.split(';').forEach((part) => {
    const idx = part.indexOf('=');
    if (idx === -1) return;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (k) tags[k] = v;
  });
  return tags;
}

export async function checkBIMI(fromDomain, selector) {
  if (!fromDomain) return { result: 'none', explanation: 'No From-domain available to check.' };

  const sel = selector || 'default';
  try {
    const res = await queryTXT(`${sel}._bimi.${fromDomain}`);
    const record = (res.records || []).find((r) => /^v=BIMI1/i.test(r));
    if (!record) {
      return { result: 'none', explanation: `No BIMI record found at ${sel}._bimi.${fromDomain}`, domain: fromDomain, selector: sel };
    }
    const tags = parseTagList(record);
    return {
      result: 'found',
      record,
      tags,
      domain: fromDomain,
      selector: sel,
      logoUrl: tags.l || null,
      authorityUrl: tags.a || null,
    };
  } catch (e) {
    return { result: 'error', explanation: e.message, domain: fromDomain, selector: sel };
  }
}

import { queryDNS, queryTXT } from './dns.js';

const MAX_DNS_LOOKUPS = 10;
const QUALIFIER_RESULT = { '+': 'pass', '-': 'fail', '~': 'softfail', '?': 'neutral' };

export async function checkSPF(domain, ip) {
  const trace = [];
  const lookupCount = { n: 0 };

  if (!domain) return { result: 'none', explanation: 'No domain available to check (missing envelope sender / From address).', trace, domain, ip };
  if (!ip) return { result: 'none', explanation: 'No sending IP address could be determined from the headers.', trace, domain, ip };

  try {
    const outcome = await evaluate(domain, ip, lookupCount, trace, 0);
    return { ...outcome, trace, domain, ip };
  } catch (e) {
    return { result: 'temperror', explanation: e.message, trace, domain, ip };
  }
}

async function getSPFRecord(domain) {
  const res = await queryTXT(domain);
  const spfRecords = (res.records || []).filter((r) => /^v=spf1(\s|$)/i.test(r));
  if (spfRecords.length === 0) return null;
  if (spfRecords.length > 1) throw new Error(`permerror: multiple SPF records published for ${domain}`);
  return spfRecords[0];
}

async function evaluate(domain, ip, lookupCount, trace, depth) {
  if (depth > 10) return { result: 'permerror', explanation: 'Too many levels of include/redirect recursion' };

  lookupCount.n++;
  if (lookupCount.n > MAX_DNS_LOOKUPS) {
    return { result: 'permerror', explanation: 'Exceeded the 10 DNS-lookup limit defined by RFC 7208' };
  }

  let record;
  try {
    record = await getSPFRecord(domain);
  } catch (e) {
    return { result: 'permerror', explanation: e.message };
  }

  trace.push({ domain, record });

  if (record === null) {
    return { result: depth === 0 ? 'none' : 'permerror', explanation: `No SPF (v=spf1) TXT record published for ${domain}` };
  }

  const terms = record.trim().split(/\s+/).slice(1);
  let redirect = null;

  for (const term of terms) {
    let qualifier = '+';
    let mech = term;
    if ('+-~?'.includes(term[0])) {
      qualifier = term[0];
      mech = term.slice(1);
    }
    const [mechName, mechArg] = splitMech(mech);
    const lname = mechName.toLowerCase();

    if (lname === 'all') {
      return finish(qualifier, `Matched 'all' at end of record for ${domain}`);
    } else if (lname === 'ip4' || lname === 'ip6') {
      if (mechArg && ipMatches(ip, mechArg)) return finish(qualifier, `IP ${ip} matches ${mech}`);
    } else if (lname === 'a') {
      lookupCount.n++;
      if (lookupCount.n > MAX_DNS_LOOKUPS) return { result: 'permerror', explanation: 'Exceeded the 10 DNS-lookup limit' };
      if (await matchesA(mechArg || domain, ip)) return finish(qualifier, `IP ${ip} matches a:${mechArg || domain}`);
    } else if (lname === 'mx') {
      lookupCount.n++;
      if (lookupCount.n > MAX_DNS_LOOKUPS) return { result: 'permerror', explanation: 'Exceeded the 10 DNS-lookup limit' };
      if (await matchesMX(mechArg || domain, ip)) return finish(qualifier, `IP ${ip} matches mx:${mechArg || domain}`);
    } else if (lname === 'include') {
      if (!mechArg) continue;
      const sub = await evaluate(mechArg, ip, lookupCount, trace, depth + 1);
      if (sub.result === 'pass') return finish(qualifier, `Matched via include:${mechArg}`);
      if (sub.result === 'permerror') return { result: 'permerror', explanation: `include:${mechArg} — ${sub.explanation}` };
      continue;
    } else if (lname === 'exists') {
      lookupCount.n++;
      if (lookupCount.n > MAX_DNS_LOOKUPS) return { result: 'permerror', explanation: 'Exceeded the 10 DNS-lookup limit' };
      try {
        const res = await queryDNS(mechArg, 'A');
        if (res.records && res.records.length) return finish(qualifier, `Matched exists:${mechArg}`);
      } catch {
        // ignore
      }
    } else if (lname === 'ptr') {
      trace.push({ note: `ptr mechanism (${mech}) skipped — deprecated by RFC 7208 and not evaluated` });
    } else if (lname === 'redirect') {
      redirect = mechArg;
    } else if (lname === 'exp') {
    }
  }

  if (redirect) {
    return evaluate(redirect, ip, lookupCount, trace, depth + 1);
  }

  return { result: 'neutral', explanation: `No mechanism matched in ${domain}; implicit neutral (no trailing 'all')` };

  function finish(qual, explanation) {
    return { result: QUALIFIER_RESULT[qual] || 'neutral', explanation };
  }
}

function splitMech(mech) {
  const colonIdx = mech.indexOf(':');
  const eqIdx = mech.indexOf('=');
  let sepIdx = -1;
  if (colonIdx === -1) sepIdx = eqIdx;
  else if (eqIdx === -1) sepIdx = colonIdx;
  else sepIdx = Math.min(colonIdx, eqIdx);
  if (sepIdx === -1) return [mech, null];
  return [mech.slice(0, sepIdx), mech.slice(sepIdx + 1)];
}

async function matchesA(name, ip) {
  try {
    const type = isIPv6(ip) ? 'AAAA' : 'A';
    const res = await queryDNS(name, type);
    return (res.records || []).some((r) => r === ip);
  } catch {
    return false;
  }
}

async function matchesMX(name, ip) {
  try {
    const res = await queryDNS(name, 'MX');
    const hosts = (res.records || []).map((r) => r.split(' ').pop().replace(/\.$/, ''));
    for (const h of hosts) {
      if (await matchesA(h, ip)) return true;
    }
    return false;
  } catch {
    return false;
  }
}

function isIPv6(ip) {
  return ip.includes(':');
}

function ipMatches(ip, cidr) {
  if (isIPv6(ip)) {
    if (!cidr.includes(':')) return false;
    return ipInCidr6(ip, cidr);
  }
  if (cidr.includes(':')) return false;
  return ipInCidr4(ip, cidr);
}

function ipToLong(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) return null;
  return (parts[0] * 16777216 + parts[1] * 65536 + parts[2] * 256 + parts[3]) >>> 0;
}

function ipInCidr4(ip, cidr) {
  const [range, bitsStr] = cidr.split('/');
  const bits = bitsStr !== undefined ? parseInt(bitsStr, 10) : 32;
  const ipLong = ipToLong(ip);
  const rangeLong = ipToLong(range);
  if (ipLong === null || rangeLong === null) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipLong & mask) === (rangeLong & mask);
}

function expandIPv6(ip) {
  let head = ip;
  let tail = null;
  if (ip.includes('::')) {
    [head, tail] = ip.split('::');
  }
  let headParts = head ? head.split(':').filter(Boolean) : [];
  let tailParts = tail ? tail.split(':').filter(Boolean) : [];
  if (tail !== null) {
    const missing = 8 - headParts.length - tailParts.length;
    headParts = headParts.concat(Array(Math.max(missing, 0)).fill('0')).concat(tailParts);
  }
  return headParts.map((p) => p.padStart(4, '0'));
}

function ipv6ToBigInt(ip) {
  const parts = expandIPv6(ip);
  if (parts.length !== 8) return null;
  let result = 0n;
  for (const p of parts) result = (result << 16n) + BigInt(parseInt(p, 16));
  return result;
}

function ipInCidr6(ip, cidr) {
  const [range, bitsStr] = cidr.split('/');
  const bits = bitsStr !== undefined ? parseInt(bitsStr, 10) : 128;
  const ipBig = ipv6ToBigInt(ip);
  const rangeBig = ipv6ToBigInt(range);
  if (ipBig === null || rangeBig === null) return false;
  const shift = BigInt(128 - bits);
  const mask = bits === 0 ? 0n : ((1n << BigInt(bits)) - 1n) << shift;
  return (ipBig & mask) === (rangeBig & mask);
}

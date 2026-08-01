import { queryTXT } from './dns.js';

export async function checkDKIMSignatures(headers, body) {
  const sigHeaders = headers.filter((h) => h.name.toLowerCase() === 'dkim-signature');
  const results = [];
  for (const sigHeader of sigHeaders) {
    results.push(await verifyOne(sigHeader, headers, body));
  }
  return results;
}

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

async function verifyOne(sigHeader, allHeaders, body) {
  const tags = parseTagList(sigHeader.unfolded);
  const domain = tags.d;
  const selector = tags.s;
  const algo = (tags.a || 'rsa-sha256').toLowerCase();
  const c = (tags.c || 'simple/simple').split('/');
  const headerCanon = c[0] || 'simple';
  const bodyCanon = c[1] || 'simple';
  const signedHeaderNames = (tags.h || '').split(':').map((s) => s.trim()).filter(Boolean);

  const info = { domain, selector, algo, headerCanon, bodyCanon, tags, raw: sigHeader.unfolded };

  if (!domain || !selector || !tags.b) {
    return { ...info, result: 'permerror', explanation: 'Missing required DKIM tag (d=, s=, or b=)' };
  }
  if (algo.startsWith('rsa-') === false) {
    return { ...info, result: 'unsupported', explanation: `Algorithm "${algo}" is not supported by this analyzer (only rsa-sha1 / rsa-sha256 are implemented)` };
  }

  let record;
  try {
    const res = await queryTXT(`${selector}._domainkey.${domain}`);
    record = (res.records || []).find((r) => /p=/.test(r));
  } catch (e) {
    return { ...info, result: 'temperror', explanation: `DNS lookup failed: ${e.message}` };
  }
  if (!record) {
    return { ...info, result: 'permerror', explanation: `No DKIM public key record found at ${selector}._domainkey.${domain}` };
  }

  const keyTags = parseTagList(record);
  info.keyRecord = record;

  if (keyTags.p === undefined || keyTags.p === '') {
    return { ...info, result: 'fail', explanation: 'Key has been revoked by the sending domain (empty p= tag)' };
  }

  if (body === null || body === undefined) {
    return {
      ...info,
      result: 'unverified',
      explanation: 'DKIM public key found in DNS. Full cryptographic verification requires the message body — upload the original .eml file to verify the signature.',
    };
  }

  try {
    const hashAlgo = algo.includes('sha256') ? 'SHA-256' : 'SHA-1';

    const canonBody = canonicalizeBody(body, bodyCanon);
    const bodyHashBuf = await crypto.subtle.digest(hashAlgo, new TextEncoder().encode(canonBody));
    const bodyHash = arrayBufferToBase64(bodyHashBuf);
    if (tags.bh && bodyHash !== tags.bh) {
      return {
        ...info,
        result: 'fail',
        explanation: 'Body hash mismatch (bh=): the message body does not match what was signed. This can also happen if the body was copy/pasted and line endings changed.',
      };
    }

    const canonHeaderLines = [];
    const used = new Map();
    for (const name of signedHeaderNames) {
      const key = name.toLowerCase();
      const count = used.get(key) || 0;
      const matches = allHeaders.filter((h) => h.name.toLowerCase() === key);
      const h = matches[matches.length - 1 - count];
      used.set(key, count + 1);
      if (!h) continue;
      canonHeaderLines.push(canonicalizeHeaderField(h.name, h.value, headerCanon));
    }
    const dkimValueNoB = sigHeader.unfolded.replace(/([;\s]b=)[^;]*/, '$1');
    canonHeaderLines.push(canonicalizeHeaderField(sigHeader.name, dkimValueNoB, headerCanon));

    const signedData = canonHeaderLines.join('\r\n');

    const keyDer = base64ToArrayBuffer(keyTags.p);
    const cryptoKey = await crypto.subtle.importKey(
      'spki',
      keyDer,
      { name: 'RSASSA-PKCS1-v1_5', hash: hashAlgo },
      false,
      ['verify']
    );
    const sigBuf = base64ToArrayBuffer(tags.b.replace(/\s+/g, ''));
    const valid = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', cryptoKey, sigBuf, new TextEncoder().encode(signedData));

    return {
      ...info,
      result: valid ? 'pass' : 'fail',
      explanation: valid
        ? 'Signature verified successfully against the public key published in DNS.'
        : 'Signature does not match. The signed headers may have been altered in transit, or (if header canonicalization is "simple") whitespace differences from copy/paste could be responsible.',
    };
  } catch (e) {
    return { ...info, result: 'error', explanation: `Verification error: ${e.message}` };
  }
}

function canonicalizeHeaderField(name, value, mode) {
  if (mode === 'relaxed') {
    const lname = name.toLowerCase();
    let v = value
      .split('\n')
      .map((l) => l.trim())
      .join(' ');
    v = v.replace(/[ \t]+/g, ' ').trim();
    return `${lname}:${v}`;
  }
  // simple: best-effort reconstruction (exact original folding is not preserved by the parser)
  return `${name}:${value.split('\n').map((l) => l.trim()).join(' ')}`;
}

function canonicalizeBody(body, mode) {
  let normalized = body.replace(/\r\n/g, '\n');
  let lines = normalized.split('\n');
  if (mode === 'relaxed') {
    lines = lines.map((l) => l.replace(/[ \t]+/g, ' ').replace(/[ \t]+$/, ''));
  }
  while (lines.length && lines[lines.length - 1] === '') lines.pop();
  if (lines.length === 0) return '';
  return lines.join('\r\n') + '\r\n';
}

function base64ToArrayBuffer(b64) {
  const bin = atob(b64.replace(/\s+/g, ''));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

function arrayBufferToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

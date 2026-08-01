export function splitHeadersAndBody(raw) {
  const normalized = raw.replace(/\r\n/g, '\n');
  const idx = normalized.indexOf('\n\n');
  if (idx === -1) return { headerBlock: normalized, body: null };
  return { headerBlock: normalized.slice(0, idx), body: normalized.slice(idx + 2) };
}

export function parseHeaders(rawHeaderBlock) {
  const lines = rawHeaderBlock.replace(/\r\n/g, '\n').split('\n').filter((l) => l.length > 0 || true);
  const headers = [];
  let current = null;

  for (const line of lines) {
    if (line === '') continue;
    if (/^[ \t]/.test(line) && current) {
      current.value += '\n' + line;
      current.raw += '\n' + line;
    } else {
      const idx = line.indexOf(':');
      if (idx === -1) {
        continue;
      }
      const name = line.slice(0, idx).trim();
      const value = line.slice(idx + 1).trim();
      current = { name, value, raw: line };
      headers.push(current);
    }
  }

  for (const h of headers) {
    h.unfolded = h.value
      .split('\n')
      .map((l) => l.trim())
      .join(' ')
      .trim();
  }

  return headers;
}

export function getHeader(headers, name) {
  const n = name.toLowerCase();
  const matches = headers.filter((h) => h.name.toLowerCase() === n);
  return matches.length ? matches[matches.length - 1] : null;
}

export function getFirstHeader(headers, name) {
  const n = name.toLowerCase();
  return headers.find((h) => h.name.toLowerCase() === n) || null;
}

export function getHeaders(headers, name) {
  const n = name.toLowerCase();
  return headers.filter((h) => h.name.toLowerCase() === n);
}

export function extractEmailAddress(value) {
  if (!value) return null;
  const match = value.match(/<([^>]+)>/);
  if (match) return match[1].trim();
  const bare = value.trim().split(/\s+/).pop();
  if (bare && bare.includes('@')) return bare.replace(/[<>,;]/g, '');
  return null;
}

export function domainFromEmail(email) {
  if (!email || !email.includes('@')) return null;
  return email.split('@').pop().replace(/[>\s]/g, '').toLowerCase();
}

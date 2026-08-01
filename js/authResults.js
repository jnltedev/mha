export function parseAuthenticationResults(headers) {
  const arHeaders = headers.filter((h) => h.name.toLowerCase() === 'authentication-results');
  return arHeaders.map((h) => parseOne(h.unfolded));
}

function parseOne(value) {
  const firstSemi = value.indexOf(';');
  const authserv = firstSemi === -1 ? value.trim() : value.slice(0, firstSemi).trim();
  const rest = firstSemi === -1 ? '' : value.slice(firstSemi + 1);

  const results = {};
  const methodRegex = /(spf|dkim|dmarc)=(\w+)([^;]*)/gi;
  let m;
  while ((m = methodRegex.exec(rest)) !== null) {
    const method = m[1].toLowerCase();
    const result = m[2].toLowerCase();
    const details = m[3].trim();
    if (!results[method]) results[method] = [];
    results[method].push({ result, details });
  }

  return { authserv, raw: value, results };
}

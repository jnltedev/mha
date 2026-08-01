const DOH_ENDPOINTS = [
  { name: 'Cloudflare', url: 'https://cloudflare-dns.com/dns-query' },
  { name: 'Google', url: 'https://dns.google/resolve' },
];

const TYPE_NUM = { A: 1, NS: 2, TXT: 16, AAAA: 28, MX: 15 };

const cache = new Map();

export async function queryTXT(name) {
  return queryDNS(name, 'TXT');
}

export async function queryDNS(name, type) {
  const key = `${type}:${name.toLowerCase()}`;
  if (cache.has(key)) return cache.get(key);

  let lastErr;
  for (const ep of DOH_ENDPOINTS) {
    try {
      const url = `${ep.url}?name=${encodeURIComponent(name)}&type=${type}`;
      const res = await fetch(url, { headers: { accept: 'application/dns-json' } });
      if (!res.ok) throw new Error(`DoH HTTP ${res.status} from ${ep.name}`);
      const data = await res.json();
      const wantNum = TYPE_NUM[type];
      const answers = (data.Answer || []).filter((a) => a.type === wantNum);
      const result = {
        status: data.Status,
        records: answers.map((a) => (type === 'TXT' ? cleanTXT(a.data) : a.data)),
        resolver: ep.name,
      };
      cache.set(key, result);
      return result;
    } catch (e) {
      lastErr = e;
      continue;
    }
  }
  throw lastErr || new Error('All DoH resolvers failed');
}

function cleanTXT(data) {
  let out = data;
  if (out.startsWith('"') && out.endsWith('"')) out = out.slice(1, -1);
  // Multiple quoted character-strings ("..." "...") concatenate directly.
  out = out.replace(/"\s*"/g, '');
  // Unescape DoH JSON TXT escaping of embedded quotes/backslashes.
  out = out.replace(/\\"/g, '"').replace(/\\\\/g, '\\');
  return out;
}

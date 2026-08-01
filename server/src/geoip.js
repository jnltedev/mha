export async function lookupIP(ip) {
  const apiKey = process.env.IPDB_API_KEY;
  if (!apiKey) {
    throw Object.assign(new Error('IPDB_API_KEY not configured'), { code: 'NO_API_KEY' });
  }

  const base = process.env.IPDB_BASE_URL;
  const res = await fetch(`${base}/lookup/${encodeURIComponent(ip)}`, {
    headers: { Authorization: `Bearer ${apiKey}` },
  });

  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw Object.assign(new Error(`IPDB lookup failed: ${res.status} ${body}`), {
      code: 'UPSTREAM_ERROR',
      status: res.status,
    });
  }

  return res.json();
}

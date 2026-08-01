export function countryCodeToFlag(code) {
  if (!code || code.length !== 2) return '';
  const upper = code.toUpperCase();
  if (!/^[A-Z]{2}$/.test(upper)) return '';
  return String.fromCodePoint(...[...upper].map((c) => 127397 + c.charCodeAt(0)));
}

export async function lookupCountry(ip) {
  try {
    const res = await fetch(`/api/geoip/${encodeURIComponent(ip)}`, { cache: 'no-store' });
    if (!res.ok) return null;
    const data = await res.json();
    const code = data && data.country && data.country.code;
    if (!code) return null;
    return { code, name: data.country.name || code, flag: countryCodeToFlag(code) };
  } catch {
    return null;
  }
}

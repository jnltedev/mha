export function parseReceivedChain(headers) {
  const received = headers.filter((h) => h.name.toLowerCase() === 'received');
  const hops = received
    .slice()
    .reverse()
    .map((h, idx) => parseHop(h.unfolded, idx));

  for (let i = 1; i < hops.length; i++) {
    if (hops[i].date && hops[i - 1].date) {
      hops[i].delaySeconds = Math.round((hops[i].date - hops[i - 1].date) / 1000);
    }
  }

  return hops;
}

function parseHop(value, index) {
  const fromHostMatch = value.match(/from\s+(\S+)/i);
  const fromDetailMatch = value.match(/from\s+\S+\s+(\([^)]*\))/i);
  const byMatch = value.match(/by\s+(\S+)/i);
  const ipMatch = value.match(/\[([0-9a-fA-F.:]+)\]/);
  const dateMatch = value.match(/;\s*(.+)$/);
  let date = null;
  if (dateMatch) {
    const parsed = new Date(dateMatch[1].trim());
    if (!isNaN(parsed.getTime())) date = parsed;
  }

  const tlsMatch = value.match(/using\s+(TLSv[\d.]+|SSLv[\d.]+)|version=(TLS\d[\d_.]*)|\bSMTPS\b/i);
  const protocolMatch = value.match(/\bwith\s+(\S+)/i);

  return {
    index,
    raw: value,
    fromHost: fromHostMatch ? fromHostMatch[1].trim() : null,
    fromDetail: fromDetailMatch ? fromDetailMatch[1].trim() : null,
    by: byMatch ? byMatch[1].trim() : null,
    ip: ipMatch ? ipMatch[1] : null,
    date,
    delaySeconds: null,
    tlsVersion: tlsMatch ? (tlsMatch[1] || tlsMatch[2] || 'TLS').replace(/_/g, '.') : null,
    protocol: protocolMatch ? protocolMatch[1].replace(/[;,]$/, '') : null,
  };
}

// LMTP (and its rarer variants) is used exclusively for local/internal handoff
// between components of the same mail stack (e.g. Postfix -> Dovecot) — it
// never crosses the public Internet, so MTAs essentially never log TLS info
// for it. Flagging "no TLS" there would be misleading, not informative.
const LOCAL_TRANSFER_PROTOCOLS = new Set(['lmtp', 'lmtpa', 'lmtps']);

export function isLocalTransferProtocol(protocol) {
  return !!protocol && LOCAL_TRANSFER_PROTOCOLS.has(protocol.toLowerCase());
}

// Best-effort guess at the IP address relevant for an SPF check, used as the
// default candidate for SPF evaluation.
//
// This intentionally picks the MOST RECENT hop with a public IP, not the
// oldest. SPF is evaluated by whichever server received the message against
// the client IP that connected *to it* — i.e. the newest "Received: from"
// header, since that's the only hop the analyzing party (or the original
// recipient's own infrastructure) can vouch for. Every earlier hop is an
// unverified claim made by upstream servers. This also matches how
// forwarded mail (e.g. via SRS rewriting) actually gets checked: the
// envelope-from domain and the connecting IP both change at the forwarder,
// so the relevant IP is the forwarder's outbound IP, not the original
// sender's IP further up the chain.
export function guessOriginatingIP(hops) {
  for (let i = hops.length - 1; i >= 0; i--) {
    const hop = hops[i];
    if (hop.ip && !isPrivateIP(hop.ip)) return { ip: hop.ip, hop };
  }
  for (let i = hops.length - 1; i >= 0; i--) {
    if (hops[i].ip) return { ip: hops[i].ip, hop: hops[i] };
  }
  return null;
}

export function isPrivateIP(ip) {
  if (ip.includes(':')) return ip === '::1' || ip.startsWith('fe80') || ip.startsWith('fc') || ip.startsWith('fd');
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4) return false;
  const [a, b] = parts;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true;
  return false;
}

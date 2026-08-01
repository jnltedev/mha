export async function createShare(type, payload) {
  const res = await fetch('/api/share', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type, payload, consent: true }),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.message || describeError(body.error) || `Share failed (HTTP ${res.status})`);
  }
  return res.json();
}

export async function fetchShareStatus(id) {
  const res = await fetch(`/api/share/${encodeURIComponent(id)}`);
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw Object.assign(new Error(describeError(body.error) || `HTTP ${res.status}`), { status: res.status, code: body.error });
  }
  return res.json();
}

export async function unlockShare(id, password) {
  const res = await fetch(`/api/share/${encodeURIComponent(id)}/unlock`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password }),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw Object.assign(new Error(describeError(body.error) || `HTTP ${res.status}`), { status: res.status, code: body.error });
  }
  return res.json();
}

function describeError(code) {
  switch (code) {
    case 'not_found':
      return 'This share link does not exist (it may have been mistyped).';
    case 'expired':
      return 'This share link has expired. Shares are only valid for 24 hours and cannot be renewed.';
    case 'invalid_password':
      return 'Incorrect password.';
    case 'password_required':
      return 'Enter the password that was shared alongside this link.';
    default:
      return null;
  }
}

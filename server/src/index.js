import express from 'express';
import crypto from 'node:crypto';
import pool, { initSchema, cleanupExpired } from './db.js';
import { encryptPayload, decryptPayload, generatePassword } from './crypto.js';
import { lookupIP } from './geoip.js';

const app = express();
app.use(express.json({ limit: '2mb' }));

const SHARE_TTL_MS = 24 * 60 * 60 * 1000;
const VALID_TYPES = new Set(['analysis', 'compare']);

function getAppUrl(req) {
  const configured = process.env.APP_URL;
  if (configured) return configured.replace(/\/$/, '');
  return `${req.protocol}://${req.get('host')}`;
}

app.get('/api/health', (req, res) => res.json({ ok: true }));

app.get('/api/geoip/:ip', async (req, res) => {
  res.set('Cache-Control', 'no-store');
  try {
    const data = await lookupIP(req.params.ip);
    res.json(data);
  } catch (e) {
    if (e.code === 'NO_API_KEY') return res.status(503).json({ error: 'geoip_not_configured' });
    console.error('geoip lookup failed:', e.message);
    res.status(502).json({ error: 'geoip_lookup_failed' });
  }
});

app.post('/api/share', async (req, res) => {
  const { type, payload, consent } = req.body || {};
  if (consent !== true) {
    return res.status(400).json({ error: 'consent_required', message: 'You must consent to encrypted storage before sharing.' });
  }
  if (!VALID_TYPES.has(type) || !payload || typeof payload !== 'object') {
    return res.status(400).json({ error: 'invalid_payload' });
  }

  try {
    const id = crypto.randomBytes(9).toString('base64url');
    const password = generatePassword();
    const { salt, iv, authTag, ciphertext } = encryptPayload(payload, password);
    const expiresAt = new Date(Date.now() + SHARE_TTL_MS);

    await pool.query(
      `INSERT INTO shares (id, type, salt, iv, auth_tag, ciphertext, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [id, type, salt, iv, authTag, ciphertext, expiresAt]
    );

    res.json({ id, password, expiresAt: expiresAt.toISOString(), url: `${getAppUrl(req)}/s/${id}` });
  } catch (e) {
    console.error('share create failed:', e);
    res.status(500).json({ error: 'share_failed' });
  }
});

app.get('/api/share/:id', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT type, created_at, expires_at FROM shares WHERE id = $1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'not_found' });
    const row = rows[0];
    if (new Date(row.expires_at) < new Date()) return res.status(410).json({ error: 'expired' });
    res.json({ type: row.type, createdAt: row.created_at, expiresAt: row.expires_at });
  } catch (e) {
    console.error('share lookup failed:', e);
    res.status(500).json({ error: 'lookup_failed' });
  }
});

app.post('/api/share/:id/unlock', async (req, res) => {
  const { password } = req.body || {};
  if (!password || typeof password !== 'string') {
    return res.status(400).json({ error: 'password_required' });
  }

  try {
    const { rows } = await pool.query('SELECT * FROM shares WHERE id = $1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'not_found' });
    const row = rows[0];
    if (new Date(row.expires_at) < new Date()) return res.status(410).json({ error: 'expired' });

    try {
      const payload = decryptPayload({ salt: row.salt, iv: row.iv, authTag: row.auth_tag, ciphertext: row.ciphertext }, password);
      res.json({ type: row.type, payload, expiresAt: row.expires_at });
    } catch {
      res.status(401).json({ error: 'invalid_password' });
    }
  } catch (e) {
    console.error('share unlock failed:', e);
    res.status(500).json({ error: 'unlock_failed' });
  }
});

app.use((err, req, res, next) => {
  if (err) {
    console.error('unhandled error:', err.message);
    return res.status(400).json({ error: 'bad_request' });
  }
  next();
});

const PORT = process.env.PORT || 3000;

async function initSchemaWithRetry(retries = 30, delayMs = 1000) {
  for (let i = 1; i <= retries; i++) {
    try {
      await initSchema();
      return;
    } catch (e) {
      if (i === retries) throw e;
      console.log(`Database not ready yet (${e.code || e.message}), retrying ${i}/${retries}…`);
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }
}

initSchemaWithRetry()
  .then(() => {
    setInterval(() => {
      cleanupExpired().catch((e) => console.error('cleanup failed:', e));
    }, 15 * 60 * 1000);
    app.listen(PORT, () => console.log(`mha-api listening on :${PORT}`));
  })
  .catch((e) => {
    console.error('Failed to initialize database schema after retries:', e);
    process.exit(1);
  });

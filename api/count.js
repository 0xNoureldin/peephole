// Global "files checked" counter for Peephole.
//
// IMPORTANT: file contents never reach this endpoint. The browser does all the
// checking locally; it calls here only to read the running total (GET) or add an
// anonymous +1 (POST). The only thing stored is a single integer.
//
// Backed by Vercel KV / Upstash Redis over its REST API, so there is no npm
// dependency and no build step. It reads whichever env-var pair your store
// provides (Vercel KV uses KV_REST_API_*, the Upstash integration uses
// UPSTASH_REDIS_REST_*). Until a store is linked it reports { configured:false }
// and the page falls back to a per-device count, so the site works either way.

const BASE = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL || '';
const TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN || '';
const KEY = 'peephole:checks';

async function redis(command) {
  const res = await fetch(`${BASE}/${command}/${KEY}`, {
    headers: { Authorization: `Bearer ${TOKEN}` },
  });
  if (!res.ok) throw new Error(`KV responded ${res.status}`);
  const data = await res.json();
  return data.result;
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  if (!BASE || !TOKEN) {
    return res.status(200).json({ total: null, configured: false });
  }

  try {
    const result = req.method === 'POST' ? await redis('incr') : await redis('get');
    const total = parseInt(result ?? 0, 10) || 0;
    return res.status(200).json({ total, configured: true });
  } catch (err) {
    return res.status(200).json({ total: null, configured: false, error: 'counter unavailable' });
  }
}

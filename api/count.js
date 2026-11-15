// Global counters for Peephole: total files checked, how many were safe, and
// how many were dangerous.
//
// IMPORTANT: file contents never reach this endpoint. The browser does all the
// checking locally; it calls here only to read the totals (GET) or add an
// anonymous +1 for a finished check (POST ?v=safe|dangerous|unknown). Only three
// integers are ever stored.
//
// Backed by Vercel KV / Upstash Redis over its REST API — no npm dependency, no
// build step. Reads whichever env-var pair the store provides. Until a store is
// linked it reports { configured:false } and the page falls back to per-device
// counts, so the site works either way.

const BASE = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL || '';
const TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN || '';
const KEYS = { total: 'peephole:checks', safe: 'peephole:safe', dangerous: 'peephole:dangerous' };

async function restGet(path) {
  const r = await fetch(`${BASE}/${path}`, { headers: { Authorization: `Bearer ${TOKEN}` } });
  if (!r.ok) throw new Error(`KV ${r.status}`);
  return (await r.json()).result;
}

async function pipeline(commands) {
  const r = await fetch(`${BASE}/pipeline`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(commands),
  });
  if (!r.ok) throw new Error(`KV ${r.status}`);
  return r.json();
}

async function readAll() {
  const res = await restGet(`mget/${KEYS.total}/${KEYS.safe}/${KEYS.dangerous}`);
  const [t, s, d] = Array.isArray(res) ? res : [0, 0, 0];
  return { total: parseInt(t ?? 0, 10) || 0, safe: parseInt(s ?? 0, 10) || 0, dangerous: parseInt(d ?? 0, 10) || 0 };
}

// Only classified verdicts count. 'unknown' (unsupported/damaged files) is
// intentionally rejected so total always equals safe + dangerous.
const ALLOWED = new Set(['safe', 'dangerous']);

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  const method = req.method || 'GET';

  // Only GET (read) and POST (increment) are supported.
  if (method !== 'GET' && method !== 'POST') {
    res.setHeader('Allow', 'GET, POST');
    return res.status(405).json({ error: 'method not allowed', allow: ['GET', 'POST'] });
  }

  let v = null;
  try { v = (new URL(req.url, 'http://local').searchParams.get('v') || '').toLowerCase(); } catch {}

  // An increment must say which bucket it belongs to. Reject a POST with no (or
  // an unrecognized) v, whether or not the store is configured.
  if (method === 'POST' && !ALLOWED.has(v)) {
    return res.status(400).json({
      error: "POST requires a 'v' parameter",
      expected: [...ALLOWED],
      example: '/api/count?v=dangerous',
    });
  }

  if (!BASE || !TOKEN) {
    return res.status(200).json({ total: null, safe: null, dangerous: null, configured: false });
  }

  try {
    if (method === 'POST') {
      const commands = [['INCR', KEYS.total]];
      if (v === 'safe') commands.push(['INCR', KEYS.safe]);
      else if (v === 'dangerous') commands.push(['INCR', KEYS.dangerous]);
      await pipeline(commands);
    }
    const totals = await readAll();
    return res.status(200).json({ ...totals, configured: true });
  } catch (err) {
    return res.status(200).json({ total: null, safe: null, dangerous: null, configured: false, error: 'counter unavailable' });
  }
}

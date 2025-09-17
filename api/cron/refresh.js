// /api/cron/refresh.js — spustí náš refresh endpoint (ručně i z CRONu)
export default async function handler(req, res) {
  try {
    const base = process.env.VERCEL_URL
      ? `https://${process.env.VERCEL_URL}`
      : 'https://puls-mind-oauth.vercel.app';

    const r = await fetch(`${base}/api/oauth/refresh`, { method: 'GET' });
    const text = await r.text();
    return res.status(r.status).send(text);
  } catch (e) {
    return res.status(500).json({ error: 'cron_failed', detail: String(e) });
  }
}

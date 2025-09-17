// /api/oauth/refresh.js — získání nového access tokenu pomocí refresh tokenu (Garmin OAuth 2.0 + PKCE)
const {
  GARMIN_CLIENT_ID,
  GARMIN_CLIENT_SECRET,
  GARMIN_TOKEN_URL = 'https://diauth.garmin.com/di-oauth2-service/oauth/token',
  GARMIN_REFRESH_TOKEN, // můžeš přebít query parametrem ?rt=...
} = process.env;

export default async function handler(req, res) {
  try {
    const rt = (req.query && req.query.rt) || GARMIN_REFRESH_TOKEN;
    if (!rt) return res.status(400).json({ error: 'missing_refresh_token', hint: 'Set GARMIN_REFRESH_TOKEN or pass ?rt=' });

    if (!GARMIN_CLIENT_ID || !GARMIN_CLIENT_SECRET)
      return res.status(500).json({ error: 'missing_env', hint: 'GARMIN_CLIENT_ID / GARMIN_CLIENT_SECRET' });

    const basic = Buffer.from(`${GARMIN_CLIENT_ID}:${GARMIN_CLIENT_SECRET}`).toString('base64');

    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: rt,
    });

    const resp = await fetch(GARMIN_TOKEN_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${basic}`,
      },
      body,
    });

    const raw = await resp.text();
    let data;
    try { data = JSON.parse(raw); } catch { data = { raw }; }

    if (!resp.ok) return res.status(resp.status).json({ error: 'refresh_failed', detail: data });

    return res.status(200).json({
      ok: true,
      token_type: data.token_type,
      scope: data.scope,
      expires_in: data.expires_in,
      access_token: data.access_token,
      refresh_token: data.refresh_token, // POZOR: může být nový — ulož do Vercel env!
    });
  } catch (err) {
    return res.status(500).json({ error: 'internal_error', detail: String(err) });
  }
}

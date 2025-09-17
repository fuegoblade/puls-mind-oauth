// /api/oauth/callback.js — Garmin OAuth 2.0 + PKCE (S256) → token exchange

const {
  GARMIN_CLIENT_ID,
  GARMIN_CLIENT_SECRET,
  REDIRECT_URI,
  GARMIN_TOKEN_URL = 'https://diauth.garmin.com/di-oauth2-service/oauth/token',
} = process.env;

// jednoduché čtení cookie z headeru
function readCookie(req, name) {
  const cookie = req.headers.cookie || '';
  const pairs = cookie.split(';').map(c => c.trim()).filter(Boolean);
  const map = {};
  for (const p of pairs) {
    const i = p.indexOf('=');
    if (i === -1) { map[p] = ''; continue; }
    map[p.slice(0, i)] = decodeURIComponent(p.slice(i + 1));
  }
  return map[name];
}

export default async function handler(req, res) {
  try {
    // musí přijít ?code=...&state=...
    const { code, state } = req.query || {};
    if (!code || !state) {
      return res.status(400).json({ error: 'invalid_request', hint: 'expected code & state' });
    }

    // CSRF + PKCE ověření
    const expectedState = readCookie(req, 'oauth_state');
    const codeVerifier  = readCookie(req, 'pkce_verifier');

    if (!expectedState || state !== expectedState) {
      return res.status(400).json({ error: 'state_mismatch' });
    }
    if (!codeVerifier) {
      return res.status(400).json({ error: 'missing_code_verifier' });
    }

    if (!GARMIN_CLIENT_ID || !GARMIN_CLIENT_SECRET || !REDIRECT_URI) {
      return res.status(500).json({ error: 'missing_env', hint: 'GARMIN_CLIENT_ID/SECRET or REDIRECT_URI' });
    }

    // tělo požadavku podle Garmin OAuth2 PKCE
    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: GARMIN_CLIENT_ID,
      client_secret: GARMIN_CLIENT_SECRET,   // necháme i v body (někdy vyžadují)
      code,
      code_verifier: codeVerifier,
      redirect_uri: REDIRECT_URI,
    });

    // Basic Auth: client_id:client_secret -> base64
    const basic = Buffer.from(`${GARMIN_CLIENT_ID}:${GARMIN_CLIENT_SECRET}`).toString('base64');

    const resp = await fetch(GARMIN_TOKEN_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
        'Authorization': `Basic ${basic}`,
      },
      body: params.toString(), // pošli jako plain form-urlencoded string
    });

    // smaž krátké cookies (už nejsou potřeba)
    res.setHeader('Set-Cookie', [
      'pkce_verifier=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax',
      'oauth_state=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax',
    ]);

    // zkus JSON, jinak vrať raw text pro snazší diagnostiku
    const raw = await resp.text();
    let data;
    try { data = JSON.parse(raw); } catch { data = { raw }; }

    if (!resp.ok) {
      return res.status(resp.status).json({ error: 'token_exchange_failed', detail: data });
    }

    // (demo) jen vracíme shrnutí
    return res.status(200).json({
      ok: true,
      token_type: data.token_type,
      scope: data.scope,
      expires_in: data.expires_in,
      access_token: data.access_token,
      refresh_token: data.refresh_token,
    });
  } catch (err) {
    return res.status(500).json({ error: 'internal_error', detail: String(err) });
  }
}

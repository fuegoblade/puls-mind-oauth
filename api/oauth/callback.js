// /api/oauth/callback.js — výměna authorization code za tokeny (PKCE)
const {
  GARMIN_CLIENT_ID,
  GARMIN_CLIENT_SECRET,
  REDIRECT_URI,
  GARMIN_TOKEN_URL = 'https://diauth.garmin.com/di-oauth2-service/oauth/token',
} = process.env;

function readCookie(req, name) {
  const cookies = req.headers.cookie || '';
  const map = Object.fromEntries(
    cookies.split(';').map((c) => {
      const i = c.indexOf('=');
      if (i === -1) return [c.trim(), ''];
      return [c.slice(0, i).trim(), decodeURIComponent(c.slice(i + 1))];
    })
  );
  return map[name];
}

export default async function handler(req, res) {
  try {
    const { code, state } = req.query || {};
    if (!code || !state) {
      return res.status(400).json({ error: 'invalid_request', hint: 'expected code & state' });
    }

    const expectedState = readCookie(req, 'oauth_state');
    const codeVerifier  = readCookie(req, 'pkce_verifier');

    if (!expectedState || state !== expectedState) {
      return res.status(400).json({ error: 'state_mismatch' });
    }
    if (!codeVerifier) {
      return res.status(400).json({ error: 'missing_code_verifier' });
    }
    if (!GARMIN_CLIENT_ID || !GARMIN_CLIENT_SECRET || !REDIRECT_URI) {
      return res.status(500).json({ error: 'missing_env' });
    }

    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: GARMIN_CLIENT_ID,
      client_secret: GARMIN_CLIENT_SECRET,
      code,
      code_verifier: codeVerifier,
      redirect_uri: REDIRECT_URI,
    });

    const resp = await fetch(GARMIN_TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });

    // smaž krátké cookies
    res.setHeader('Set-Cookie', [
      'pkce_verifier=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax',
      'oauth_state=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax',
    ]);

    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      return res.status(resp.status).json({ error: 'token_exchange_failed', detail: data });
    }

    // POZOR: v produkci sem dej uložení tokenů; teď jen vrátíme shrnutí
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

// /api/oauth/start.js — Garmin OAuth 2.0 + PKCE (S256)
import crypto from 'crypto';

const {
  GARMIN_CLIENT_ID,
  REDIRECT_URI,                        // např. https://puls-mind-oauth.vercel.app/api/oauth/callback
  GARMIN_SCOPES = 'profile activity', // odděleno mezerou
  GARMIN_AUTH_URL = 'https://connect.garmin.com/oauth2Confirm',
} = process.env;

// base64url bez '=' a se správnou náhradou znaků
function b64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export default async function handler(req, res) {
  try {
    if (!GARMIN_CLIENT_ID || !REDIRECT_URI) {
      return res.status(500).json({ error: 'missing_env', hint: 'GARMIN_CLIENT_ID or REDIRECT_URI' });
    }

    // PKCE: code_verifier (43–128 znaků) a z něj S256 code_challenge
    const codeVerifier = b64url(crypto.randomBytes(64));
    const codeChallenge = b64url(crypto.createHash('sha256').update(codeVerifier).digest());

    // CSRF ochrana
    const state = b64url(crypto.randomBytes(16));

    // Ulož krátkodobé cookies (5 minut)
    const maxAge = 5 * 60;
    res.setHeader('Set-Cookie', [
      `pkce_verifier=${codeVerifier}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`,
      `oauth_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`,
    ]);

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: GARMIN_CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: GARMIN_SCOPES,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      state,
    });

    return res.redirect(302, `${GARMIN_AUTH_URL}?${params.toString()}`);
  } catch (err) {
    return res.status(500).json({ error: 'internal_error', detail: String(err) });
  }
}

// /api/oauth/start.js
import crypto from 'crypto';

const {
  GARMIN_CONSUMER_KEY,
  GARMIN_CONSUMER_SECRET,
  GARMIN_REQUEST_TOKEN_URL = 'https://connectapi.garmin.com/oauth-service/oauth/request_token',
  GARMIN_AUTH_URL = 'https://connect.garmin.com/oauthConfirm',
  REDIRECT_URI, // např. https://puls-mind-oauth.vercel.app/api/oauth/callback
} = process.env;

// RFC3986-safe percent-encoding (OAuth 1.0a vyžaduje ještě ! ' ( ) * navíc)
const enc = (s) =>
  encodeURIComponent(s)
    .replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());

const normalizeParams = (params) => {
  const pairs = [];
  Object.keys(params).forEach((k) => {
    const v = params[k];
    if (v === undefined || v === null) return;
    if (Array.isArray(v)) {
      v.forEach((item) => pairs.push([enc(k), enc(String(item))]));
    } else {
      pairs.push([enc(k), enc(String(v))]);
    }
  });
  pairs.sort((a, b) => (a[0] === b[0] ? (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0) : a[0] < b[0] ? -1 : 1));
  return pairs.map(([k, v]) => `${k}=${v}`).join('&');
};

const baseString = (method, url, params) =>
  `${method.toUpperCase()}&${enc(url)}&${enc(normalizeParams(params))}`;

const sign = (base, consumerSecret, tokenSecret = '') =>
  crypto
    .createHmac('sha1', `${enc(consumerSecret)}&${enc(tokenSecret)}`)
    .update(base)
    .digest('base64');

export default async function handler(req, res) {
  try {
    if (!GARMIN_CONSUMER_KEY || !GARMIN_CONSUMER_SECRET) {
      return res.status(500).json({ error: 'Missing Garmin consumer key/secret' });
    }
    if (!REDIRECT_URI) {
      return res.status(500).json({ error: 'Missing REDIRECT_URI' });
    }

    const method = 'POST';
    const url = 'https://connectapi.garmin.com/oauth-service/oauth/request_token';

    const oauth = {
      oauth_consumer_key: GARMIN_CONSUMER_KEY,
      oauth_nonce: crypto.randomBytes(16).toString('hex'),
      oauth_signature_method: 'HMAC-SHA1',
      oauth_timestamp: Math.floor(Date.now() / 1000).toString(),
      oauth_version: '1.0',
      oauth_callback: REDIRECT_URI, // MUSÍ být i v podpisu
    };

    const base = baseString(method, url, oauth);
    const oauth_signature = sign(base, GARMIN_CONSUMER_SECRET);

    // Authorization header (hodnoty percent-encoded, seřazené)
    const authHeader =
      'OAuth ' +
      Object.entries({ ...oauth, oauth_signature })
        .sort(([a], [b]) => (a < b ? -1 : 1))
        .map(([k, v]) => `${enc(k)}="${enc(v)}"`)
        .join(', ');

    const resp = await fetch(url, {
      method,
      headers: {
        Authorization: authHeader,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      // tělo prázdné – parametry jsou jen v OAuth headeru (a v podpisu)
    });

    const text = await resp.text();
    if (!resp.ok) {
      return res.status(401).json({ error: 'request_token_failed', detail: text });
    }

    // odpověď je query-string: oauth_token=...&oauth_token_secret=...&oauth_callback_confirmed=true
    const params = Object.fromEntries(new URLSearchParams(text));
    if (!params.oauth_token) {
      return res.status(500).json({ error: 'bad_response', detail: text });
    }

    // přesměruj uživatele na Garmin autorizační stránku
    const redirectTo = `${GARMIN_AUTH_URL}?oauth_token=${encodeURIComponent(params.oauth_token)}`;
    return res.redirect(302, redirectTo);
  } catch (e) {
    return res.status(500).json({ error: 'internal_error', detail: String(e) });
  }
}

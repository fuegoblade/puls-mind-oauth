// /api/oauth/start.js
import crypto from 'crypto';

const {
  GARMIN_CONSUMER_KEY,
  GARMIN_CONSUMER_SECRET,
  GARMIN_REQUEST_TOKEN_URL = 'https://connectapi.garmin.com/oauth-service/oauth/request_token',
  GARMIN_AUTH_URL = 'https://connect.garmin.com/oauthConfirm',
  REDIRECT_URI,
} = process.env;

// ⬇️ bezpečně ořež hodnoty z env (typická past = skrytá mezera/nový řádek)
const CK = (GARMIN_CONSUMER_KEY || '').trim();
const CS = (GARMIN_CONSUMER_SECRET || '').trim();
const CB = (REDIRECT_URI || '').trim();

// RFC3986-safe percent-encoding
const enc = (s) =>
  encodeURIComponent(s).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());

const normalizeParams = (params) => {
  const pairs = [];
  Object.keys(params).forEach((k) => {
    const v = params[k];
    if (v === undefined || v === null) return;
    if (Array.isArray(v)) v.forEach((item) => pairs.push([enc(k), enc(String(item))]));
    else pairs.push([enc(k), enc(String(v))]);
  });
  pairs.sort((a, b) => (a[0] === b[0] ? (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0) : a[0] < b[0] ? -1 : 1));
  return pairs.map(([k, v]) => `${k}=${v}`).join('&');
};

const baseString = (method, url, params) =>
  `${method.toUpperCase()}&${enc(url)}&${enc(normalizeParams(params))}`;

// ⬇️ změněno: pro Garmin podepisuj “raw” secret (bez enc) a prázdný tokenSecret
const sign = (base, consumerSecret, tokenSecret = '') =>
  crypto.createHmac('sha1', `${consumerSecret}&${tokenSecret}`).update(base).digest('base64');

export default async function handler(req, res) {
  try {
    if (!CK || !CS) return res.status(500).json({ error: 'Missing Garmin consumer key/secret' });
    if (!CB) return res.status(500).json({ error: 'Missing REDIRECT_URI' });

    const method = 'POST';
    const url = GARMIN_REQUEST_TOKEN_URL;

    const oauth = {
      oauth_consumer_key: CK,
      oauth_nonce: crypto.randomBytes(16).toString('hex'),
      oauth_signature_method: 'HMAC-SHA1',
      oauth_timestamp: Math.floor(Date.now() / 1000).toString(),
      oauth_version: '1.0',
      oauth_callback: CB, // musí být i v podpisu
    };

    const base = baseString(method, url, oauth);
    const oauth_signature = sign(base, CS);

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
    });

    const text = await resp.text();
    if (!resp.ok) {
      return res.status(401).json({ error: 'request_token_failed', detail: text });
    }

    const params = Object.fromEntries(new URLSearchParams(text));
    if (!params.oauth_token) {
      return res.status(500).json({ error: 'bad_response', detail: text });
    }

    const redirectTo = `${GARMIN_AUTH_URL}?oauth_token=${encodeURIComponent(params.oauth_token)}`;
    return res.redirect(302, redirectTo);
  } catch (e) {
    return res.status(500).json({ error: 'internal_error', detail: String(e) });
  }
}

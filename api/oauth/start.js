// /api/oauth/start.js
import crypto from 'crypto';

const {
  GARMIN_CONSUMER_KEY,
  GARMIN_CONSUMER_SECRET,
  REDIRECT_URI,
  GARMIN_AUTH_URL = 'https://connect.garmin.com/oauthConfirm',
} = process.env;

// RFC3986-safe percent-encoding (navíc ! ' ( ) *)
const enc = (s) =>
  encodeURIComponent(s).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());

const normalizeParams = (params) => {
  const pairs = [];
  for (const k of Object.keys(params)) {
    const v = params[k];
    if (v === undefined || v === null) continue;
    if (Array.isArray(v)) v.forEach(item => pairs.push([enc(k), enc(String(item))]));
    else pairs.push([enc(k), enc(String(v))]);
  }
  pairs.sort((a, b) => (a[0] === b[0] ? (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0) : (a[0] < b[0] ? -1 : 1)));
  return pairs.map(([k, v]) => `${k}=${v}`).join('&');
};

const baseString = (method, url, params) =>
  `${method.toUpperCase()}&${enc(url)}&${enc(normalizeParams(params))}`;

// ⬇️ KLÍČ BEZ percent-encodingu (důležité pro Garmin)
const sign = (base, consumerSecret, tokenSecret = '') =>
  crypto.createHmac('sha1', `${consumerSecret}&${tokenSecret}`).update(base).digest('base64');

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

    // OAuth1 params — callback MUSÍ být v podpisu
    const oauth = {
      oauth_callback: REDIRECT_URI,
      oauth_consumer_key: GARMIN_CONSUMER_KEY,
      oauth_nonce: crypto.randomBytes(16).toString('hex'),
      oauth_signature_method: 'HMAC-SHA1',
      oauth_timestamp: Math.floor(Date.now() / 1000).toString(),
      oauth_version: '1.0',
    };

    const base = baseString(method, url, oauth);
    const oauth_signature = sign(base, GARMIN_CONSUMER_SECRET);

    // Authorization header (hodnoty percent-encoded a seřazené)
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
        // někteří poskytovatelé jsou citliví na zbytečný Content-Type bez těla; vynecháme
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

    return res.redirect(302, `${GARMIN_AUTH_URL}?oauth_token=${encodeURIComponent(params.oauth_token)}`);
  } catch (e) {
    return res.status(500).json({ error: 'internal_error', detail: String(e) });
  }
}

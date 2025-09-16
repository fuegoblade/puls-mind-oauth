// /api/oauth/start.js
import crypto from 'crypto';

const RAW = {
  GARMIN_CONSUMER_KEY: process.env.GARMIN_CONSUMER_KEY || '',
  GARMIN_CONSUMER_SECRET: process.env.GARMIN_CONSUMER_SECRET || '',
  GARMIN_REQUEST_TOKEN_URL: process.env.GARMIN_REQUEST_TOKEN_URL
    || 'https://connectapi.garmin.com/oauth-service/oauth/request_token',
  GARMIN_AUTH_URL: process.env.GARMIN_AUTH_URL
    || 'https://connect.garmin.com/oauthConfirm',
  REDIRECT_URI: process.env.REDIRECT_URI || '',
};

// ořízni případné mezery/nové řádky
const CFG = Object.fromEntries(Object.entries(RAW).map(([k, v]) => [k, v.trim()]));
const {
  GARMIN_CONSUMER_KEY,
  GARMIN_CONSUMER_SECRET,
  GARMIN_REQUEST_TOKEN_URL,
  GARMIN_AUTH_URL,
  REDIRECT_URI,
} = CFG;

// RFC3986 safe encode (OAuth 1.0a ještě navíc ! ' ( ) *)
const enc = (s) =>
  encodeURIComponent(s)
    .replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());

const normalizeParams = (params) => {
  const pairs = [];
  Object.keys(params).forEach((k) => {
    const v = params[k];
    if (v === undefined || v === null) return;
    if (Array.isArray(v)) v.forEach((i) => pairs.push([enc(k), enc(String(i))]));
    else pairs.push([enc(k), enc(String(v))]);
  });
  pairs.sort((a, b) => (a[0] === b[0] ? (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0) : a[0] < b[0] ? -1 : 1));
  return pairs.map(([k, v]) => `${k}=${v}`).join('&');
};

const baseString = (method, url, params) =>
  `${method.toUpperCase()}&${enc(url)}&${enc(normalizeParams(params))}`;

const sign = (base, consumerSecret, tokenSecret = '') =>
  crypto.createHmac('sha1', `${enc(consumerSecret)}&${enc(tokenSecret)}`).update(base).digest('base64');

export default async function handler(req, res) {
  try {
    if (!GARMIN_CONSUMER_KEY || !GARMIN_CONSUMER_SECRET) {
      return res.status(500).json({ error: 'Missing Garmin consumer key/secret' });
    }
    if (!REDIRECT_URI) {
      return res.status(500).json({ error: 'Missing REDIRECT_URI' });
    }

    const method = 'POST';
    const url = GARMIN_REQUEST_TOKEN_URL;

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

    const authHeader =
      'OAuth ' +
      Object.entries({ ...oauth, oauth_signature })
        .sort(([a], [b]) => (a < b ? -1 : 1))
        .map(([k, v]) => `${enc(k)}="${enc(v)}"`)
        .join(', ');

    // Pošleme oauth_callback i v těle (některé brány to vyžadují)
    const body = new URLSearchParams({ oauth_callback: REDIRECT_URI }).toString();

    const r = await fetch(url, {
      method,
      headers: {
        Authorization: authHeader,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': String(body.length),
      },
      body,
    });

    const text = await r.text();
    if (!r.ok) {
      return res.status(r.status).json({ error: 'request_token_failed', detail: text });
    }

    const params = Object.fromEntries(new URLSearchParams(text));
    if (!params.oauth_token) {
      return res.status(500).json({ error: 'bad_response', detail: text });
    }

    return res.redirect(302, `${GARMIN_AUTH_URL}?oauth_token=${encodeURIComponent(params.oauth_token)}`);
  } catch (err) {
    return res.status(500).json({ error: 'internal_error', detail: String(err) });
  }
}

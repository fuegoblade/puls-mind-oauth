// /api/oauth/callback.js
import crypto from 'crypto';

const RAW = {
  GARMIN_CONSUMER_KEY: process.env.GARMIN_CONSUMER_KEY || '',
  GARMIN_CONSUMER_SECRET: process.env.GARMIN_CONSUMER_SECRET || '',
  GARMIN_ACCESS_TOKEN_URL:
    process.env.GARMIN_ACCESS_TOKEN_URL ||
    'https://connectapi.garmin.com/oauth-service/oauth/access_token',
};

// trim – ochrana proti skrytým mezerám/řádkům
const CFG = Object.fromEntries(Object.entries(RAW).map(([k, v]) => [k, v.trim()]));
const { GARMIN_CONSUMER_KEY, GARMIN_CONSUMER_SECRET, GARMIN_ACCESS_TOKEN_URL } = CFG;

// RFC3986 encode (OAuth1 navíc ! ' ( ) * )
const enc = (s) =>
  encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());

const normalize = (obj) => {
  const pairs = [];
  for (const k of Object.keys(obj)) {
    const v = obj[k];
    if (v === undefined || v === null) continue;
    if (Array.isArray(v)) v.forEach((x) => pairs.push([enc(k), enc(String(x))]));
    else pairs.push([enc(k), enc(String(v))]);
  }
  pairs.sort((a, b) => (a[0] === b[0] ? (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0) : a[0] < b[0] ? -1 : 1));
  return pairs.map(([k, v]) => `${k}=${v}`).join('&');
};

const baseString = (method, url, params) =>
  `${method.toUpperCase()}&${enc(url)}&${enc(normalize(params))}`;

// HMAC klíč = raw consumerSecret & tokenSecret (neenkódovat!)
const sign = (base, consumerSecret, tokenSecret = '') =>
  crypto.createHmac('sha1', `${consumerSecret}&${tokenSecret}`).update(base).digest('base64');

function getCookie(req, name) {
  const raw = req.headers.cookie || '';
  for (const part of raw.split(';')) {
    const [k, v] = part.trim().split('=');
    if (k === name) return decodeURIComponent(v || '');
  }
  return '';
}

export default async function handler(req, res) {
  try {
    const { oauth_token, oauth_verifier } = req.query || {};
    if (!oauth_token || !oauth_verifier) {
      return res
        .status(400)
        .json({ error: 'invalid_request', hint: 'expected oauth_token & oauth_verifier in query' });
    }
    if (!GARMIN_CONSUMER_KEY || !GARMIN_CONSUMER_SECRET) {
      return res.status(500).json({ error: 'missing_consumer_creds' });
    }

    // pokus o vyzvednutí request token secret z cookie (pokud ho start.js nastavil)
    const requestTokenSecret = getCookie(req, 'rt_secret') || '';

    const method = 'POST';
    const url = GARMIN_ACCESS_TOKEN_URL;

    const oauth = {
      oauth_consumer_key: GARMIN_CONSUMER_KEY,
      oauth_token,            // request token od Garminu
      oauth_verifier,         // verifier od Garminu
      oauth_nonce: crypto.randomBytes(16).toString('hex'),
      oauth_signature_method: 'HMAC-SHA1',
      oauth_timestamp: Math.floor(Date.now() / 1000).toString(),
      oauth_version: '1.0',
    };

    // podpis – použijeme token secret z cookie, pokud je k dispozici
    const base = baseString(method, url, oauth);
    const oauth_signature = sign(base, GARMIN_CONSUMER_SECRET, requestTokenSecret);

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
      // speciální nápověda, když chybí request token secret (nejčastější příčina 401 na access_token)
      const hint =
        !requestTokenSecret
          ? 'missing_request_token_secret: nastav v /api/oauth/start.js uložení oauth_token_secret do cookie rt_secret'
          : undefined;
      return res.status(resp.status).json({ error: 'access_token_failed', detail: text, hint });
    }

    // odpověď je querystring: oauth_token (access), oauth_token_secret (access), user info…
    const params = Object.fromEntries(new URLSearchParams(text));
    const safe = (s = '') => (s.length > 10 ? `${s.slice(0, 6)}…${s.slice(-4)}` : s);

    // TODO: ulož bezpečně access tokeny (DB/KV). Zatím jen vrátíme maskovaně.
    return res.status(200).json({
      message: 'Garmin OAuth connected 🎉',
      access_token: safe(params.oauth_token),
      access_token_secret: safe(params.oauth_token_secret),
      raw: { userId: params.userId || params.xmppJid || undefined },
    });
  } catch (e) {
    return res.status(500).json({ error: 'callback_exception', detail: String(e) });
  }
}

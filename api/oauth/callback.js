// /api/oauth/start.js
import crypto from "crypto";

function percentEncode(str) {
  return encodeURIComponent(str)
    .replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}

function buildOAuthHeader({ url, method, extraParams = {}, tokenSecret = "" }) {
  const params = {
    oauth_consumer_key: process.env.GARMIN_CONSUMER_KEY,
    oauth_nonce: crypto.randomBytes(16).toString("hex"),
    oauth_signature_method: "HMAC-SHA1",
    oauth_timestamp: Math.floor(Date.now() / 1000).toString(),
    oauth_version: "1.0",
    ...extraParams, // např. oauth_callback nebo oauth_token, oauth_verifier
  };

  // base string
  const normParams = Object.keys(params)
    .sort()
    .map(k => `${percentEncode(k)}=${percentEncode(params[k])}`)
    .join("&");

  const baseString = [
    method.toUpperCase(),
    percentEncode(url),
    percentEncode(normParams),
  ].join("&");

  const signingKey =
    `${percentEncode(process.env.GARMIN_CONSUMER_SECRET)}&${percentEncode(tokenSecret)}`;

  const signature = crypto
    .createHmac("sha1", signingKey)
    .update(baseString)
    .digest("base64");

  const headerParams = {
    ...params,
    oauth_signature: signature,
  };

  const authHeader =
    "OAuth " +
    Object.keys(headerParams)
      .sort()
      .map(k => `${percentEncode(k)}="${percentEncode(headerParams[k])}"`)
      .join(", ");

  return authHeader;
}

export default async function handler(req, res) {
  try {
    const requestUrl = process.env.GARMIN_REQUEST_TOKEN_URL;
    const callbackUrl = process.env.CALLBACK_URL;

    if (!requestUrl || !callbackUrl) {
      return res.status(500).json({ error: "Missing env (REQUEST_TOKEN_URL/CALLBACK_URL)" });
    }

    const Authorization = buildOAuthHeader({
      url: requestUrl,
      method: "POST",
      extraParams: { oauth_callback: callbackUrl },
    });

    const rsp = await fetch(requestUrl, {
      method: "POST",
      headers: { Authorization },
    });

    const text = await rsp.text(); // např. "oauth_token=...&oauth_token_secret=...&oauth_callback_confirmed=true"
    if (!rsp.ok) return res.status(502).json({ error: "request_token_failed", detail: text });

    const params = Object.fromEntries(new URLSearchParams(text));
    const { oauth_token, oauth_token_secret } = params;

    if (!oauth_token || !oauth_token_secret) {
      return res.status(502).json({ error: "bad_request_token_response", detail: text });
    }

    // ulož tajně request token secret do krátkodobého cookie (na výměnu v callbacku)
    res.setHeader("Set-Cookie", `rt_secret=${encodeURIComponent(oauth_token_secret)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=300`);

    const authorizeBase = process.env.GARMIN_AUTHORIZE_URL || "https://connect.garmin.com/oauthConfirm";
    const redirectTo = `${authorizeBase}?oauth_token=${encodeURIComponent(oauth_token)}`;

    res.writeHead(302, { Location: redirectTo });
    res.end();
  } catch (e) {
    res.status(500).json({ error: "start_exception", detail: e?.message });
  }
}

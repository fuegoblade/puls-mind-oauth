// /api/oauth/callback.js
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
    ...extraParams,
  };

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

  const headerParams = { ...params, oauth_signature: signature };

  const authHeader =
    "OAuth " +
    Object.keys(headerParams)
      .sort()
      .map(k => `${percentEncode(k)}="${percentEncode(headerParams[k])}"`)
      .join(", ");

  return authHeader;
}

function getCookie(req, name) {
  const raw = req.headers.cookie || "";
  for (const part of raw.split(";")) {
    const [k, v] = part.trim().split("=");
    if (k === name) return decodeURIComponent(v || "");
  }
  return "";
}

export default async function handler(req, res) {
  try {
    const { oauth_token, oauth_verifier } = req.query || {};
    if (!oauth_token || !oauth_verifier) {
      return res.status(400).json({ error: "invalid_request", hint: "expected oauth_token & oauth_verifier" });
    }

    // vyzvedni tajný request token secret z cookie
    const rtSecret = getCookie(req, "rt_secret");
    if (!rtSecret) return res.status(400).json({ error: "missing_request_token_secret" });

    const accessUrl = process.env.GARMIN_ACCESS_TOKEN_URL;

    const Authorization = buildOAuthHeader({
      url: accessUrl,
      method: "POST",
      extraParams: { oauth_token, oauth_verifier },
      tokenSecret: rtSecret,
    });

    const rsp = await fetch(accessUrl, {
      method: "POST",
      headers: { Authorization },
    });

    const text = await rsp.text(); // "oauth_token=...&oauth_token_secret=...&..."
    if (!rsp.ok) return res.status(502).json({ error: "access_token_failed", detail: text });

    const params = Object.fromEntries(new URLSearchParams(text));
    // POZOR: tady je máš – ulož si je bezpečně (DB/KV). Zatím je jen ukážeme maskované.
    res.status(200).json({
      message: "Garmin OAuth connected 🎉",
      access_token: (params.oauth_token || "").slice(0, 6) + "…",
      access_token_secret: (params.oauth_token_secret || "").slice(0, 6) + "…",
    });
  } catch (e) {
    res.status(500).json({ error: "callback_exception", detail: e?.message });
  }
}

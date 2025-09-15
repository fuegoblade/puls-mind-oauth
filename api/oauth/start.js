// /api/oauth/start.js
export default function handler(req, res) {
  const base = process.env.GARMIN_AUTH_URL; // z Garmin Portalu (Authorization URL)
  if (!base) {
    return res.status(500).json({ error: "GARMIN_AUTH_URL is not set" });
  }

  const params = new URLSearchParams({
    client_id: process.env.GARMIN_CLIENT_ID,
    response_type: "code",
    redirect_uri: process.env.REDIRECT_URI,
    scope:
      process.env.GARMIN_SCOPES ||
      "health:read wellness:read sleep:read activities:read",
  });

  res.writeHead(302, { Location: `${base}?${params.toString()}` });
  res.end();
}

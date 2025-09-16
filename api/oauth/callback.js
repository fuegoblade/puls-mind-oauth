export default function handler(req, res) {
  const { code, error } = req.query;
  if (error) return res.status(400).json({ error });
  if (!code) return res.status(400).json({ error: "Missing code" });
  res.status(200).json({ message: "PulseMind OAuth callback alive ✅", code });
}

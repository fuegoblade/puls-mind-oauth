// api/oauth/start.js

import OAuth from 'oauth';

export default function handler(req, res) {
  const oauth = new OAuth.OAuth(
    process.env.GARMIN_REQUEST_TOKEN_URL,
    process.env.GARMIN_ACCESS_TOKEN_URL,
    process.env.GARMIN_CONSUMER_KEY,
    process.env.GARMIN_CONSUMER_SECRET,
    '1.0',
    process.env.REDIRECT_URI,
    'HMAC-SHA1'
  );

  oauth.getOAuthRequestToken((error, oauthToken, oauthTokenSecret) => {
    if (error) {
      console.error('Error obtaining request token:', error);
      res.status(500).json({ error: 'Failed to obtain request token' });
    } else {
      // Dočasně si token_secret můžeš uložit do session/DB (pokud chceš)
      res.redirect(`${process.env.GARMIN_AUTH_URL}?oauth_token=${oauthToken}`);
    }
  });
}

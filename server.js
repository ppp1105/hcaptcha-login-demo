require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// TRUST_PROXY tells Express to trust X-Forwarded-For to get the real client
// IP behind a reverse proxy/load balancer/CDN. Without this in production,
// IP-based rate limiting loses effect (all traffic appears to come from the
// proxy's IP) or becomes vulnerable to header spoofing. Leave unset in local
// dev (no proxy in front). See https://expressjs.com/en/guide/behind-proxies.html
if (process.env.TRUST_PROXY) {
  const asNumber = Number(process.env.TRUST_PROXY);
  app.set('trust proxy', Number.isNaN(asNumber) ? process.env.TRUST_PROXY : asNumber);
}

app.disable('x-powered-by');
app.use(
  helmet({
    // hCaptcha's CDN does not send Cross-Origin-Resource-Policy; helmet's
    // default COEP would silently block the widget.
    crossOriginEmbedderPolicy: false,
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", 'https://js.hcaptcha.com', 'https://*.hcaptcha.com'],
        frameSrc: ["'self'", 'https://*.hcaptcha.com', 'https://hcaptcha.com'],
        // The widget injects its own inline styles.
        styleSrc: ["'self'", "'unsafe-inline'", 'https://*.hcaptcha.com'],
        connectSrc: ["'self'", 'https://*.hcaptcha.com', 'https://hcaptcha.com'],
        imgSrc: ["'self'", 'https://*.hcaptcha.com', 'data:'],
      },
    },
  })
);
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// The sitekey is public by nature, it can go to the frontend with no
// security risk.
app.get('/api/config', (req, res) => {
  res.json({ sitekey: process.env.HCAPTCHA_SITEKEY });
});

// Fake user, just for the simulation. In a real system, a password is never
// stored in plain text - use a hash (bcrypt/argon2) and compare the hash.
const FAKE_USERS = { 'admin@demo.com': 'Password123!' };

// Rate limit by IP: mitigates OAT-007 Credential Cracking and OAT-008
// Credential Stuffing (reduces the volume of automated attempts on the
// login endpoint).
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'too_many_attempts' },
});

// Rate limit by account (key = email, not IP): complements the IP-based
// limit against distributed credential stuffing (many sources, few attempts
// each, same target account - OAT-008). Shared sliding window, not a
// permanent account lockout, so it doesn't open a DoS vector against the
// legitimate user (OAT-015) - same reasoning as the IP-based limit above.
const accountLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'too_many_attempts' },
  keyGenerator: (req) => {
    const { email } = req.body || {};
    return typeof email === 'string' && email ? email.trim().toLowerCase() : req.ip;
  },
});

const MAX_EMAIL_LENGTH = 254; // RFC 5321 limit
const MAX_PASSWORD_LENGTH = 256;

function credentialsAreValid(email, password) {
  return (
    typeof email === 'string' &&
    email.length > 0 &&
    email.length <= MAX_EMAIL_LENGTH &&
    typeof password === 'string' &&
    password.length > 0 &&
    password.length <= MAX_PASSWORD_LENGTH
  );
}

app.post('/api/login', loginLimiter, accountLimiter, async (req, res) => {
  const { email, password, captchaToken } = req.body || {};

  if (!credentialsAreValid(email, password)) {
    return res.status(400).json({ error: 'invalid_request' });
  }

  if (typeof captchaToken !== 'string' || !captchaToken) {
    return res.status(400).json({ error: 'captcha_required' });
  }

  let verifyData;
  try {
    const verifyRes = await fetch('https://api.hcaptcha.com/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        secret: process.env.HCAPTCHA_SECRET,
        response: captchaToken,
        remoteip: req.ip,
      }),
    });
    verifyData = await verifyRes.json();
  } catch (err) {
    console.error('[hcaptcha] error calling siteverify:', err.message);
    return res.status(502).json({ error: 'captcha_verification_unavailable' });
  }

  if (!verifyData.success) {
    console.warn('[hcaptcha] token rejected:', verifyData['error-codes']);
    return res.status(401).json({ error: 'captcha_failed' });
  }

  // Defense in depth: the hostname where the token was solved must match
  // the expected domain. Only takes effect if HCAPTCHA_EXPECTED_HOSTNAME is
  // set (optional in local dev).
  const expectedHostname = process.env.HCAPTCHA_EXPECTED_HOSTNAME;
  if (expectedHostname && verifyData.hostname !== expectedHostname) {
    console.warn('[hcaptcha] unexpected hostname in token:', verifyData.hostname);
    return res.status(401).json({ error: 'captcha_failed' });
  }

  // Deliberately generic error message: it does not reveal whether the
  // email exists or whether only the password was wrong (mitigates user
  // enumeration - OAT-004/OAT-018).
  const passwordMatches = FAKE_USERS[email] === password;
  if (!passwordMatches) {
    return res.status(401).json({ error: 'invalid_credentials' });
  }

  res.json({ ok: true, message: `Welcome, ${email}!` });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});

# PoC — Login Protected Against Automation and Fraud (hCaptcha)

Proof of concept of a login screen with **hCaptcha integrated correctly on
the server side**, surrounded by the controls that are usually missing
when only the widget is dropped into the frontend. The goal is to
demonstrate the integration pattern and the layers of defense around it —
not just the visual captcha.

## The problem

Every public login screen on the internet is a target for automated
traffic: lists of leaked credentials tested at scale (*credential
stuffing*), brute-force attempts against a specific account, scans to
discover which emails have an account (*enumeration*). This drives up
infrastructure cost, leads to compromised accounts and fraud — and a
poorly integrated captcha (frontend-only, with no real backend check)
stops none of it.

This PoC shows the correct **server-side** hCaptcha integration together
with a set of complementary controls, to serve as an architecture
reference before any larger investment.

## What this PoC demonstrates live

- **The captcha is actually verified.** The frontend only generates a
  token; the backend is what calls the official hCaptcha API
  (`siteverify`) with the secret key and decides whether the challenge was
  really solved. A token forged on the client does not pass.
- **The secret key is never exposed.** It only lives on the server, loaded
  from an environment variable — it never appears in the HTML, in the
  browser's JS, or in version control.
- **Brute-force attempts are contained.** A limit per IP (attack
  concentrated from one source) and, independently, a limit per
  account/email (attack distributed across many IPs against the same
  target) — without permanently locking out the legitimate user.
- **The system doesn't help anyone probing for valid accounts.** Error
  responses are generic ("invalid email or password"); they don't reveal
  whether the email exists or whether only the password was wrong.
- **The browser's attack surface is reduced.** Security HTTP headers (CSP,
  HSTS, anti-clickjacking) restrict what the page can load and from where
  — only what the site itself and the hCaptcha widget actually need.

## Security mechanisms implemented

| Mechanism | Business risk it mitigates | Technical reference |
|---|---|---|
| Server-side token verification (`siteverify`) | Forged/bypassed captcha on the client | Official hCaptcha server-side pattern |
| Secret key kept server-side only (`.env`, out of git) | Leaked credential that would let someone forge approvals | Secret management best practice |
| Rate limit by IP (10 attempts/15min) | Brute force concentrated from one source | OWASP OAT-007 Credential Cracking |
| Rate limit by account/email (5 attempts/15min) | Credential stuffing distributed across many IPs | OWASP OAT-008 Credential Stuffing |
| No permanent account lockout | Avoids turning the control itself into a denial-of-service weapon against the legitimate user | OWASP OAT-015 Denial of Service |
| Generic error messages | Reconnaissance of valid accounts for a follow-up attack | OWASP OAT-004 Fingerprinting / OAT-018 Footprinting |
| Input validation (type/length of email and password) | Abuse of the endpoint with malformed payloads | Boundary validation best practice |
| Security headers (`helmet`: CSP, HSTS, X-Frame-Options...) | Clickjacking, third-party script injection, MIME sniffing | OWASP Secure Headers |
| Optional verification of the token's `hostname` | Token replay outside the expected domain | Defense in depth on top of the sitekey's own scope |
| Single-use captcha token (reset after every attempt) | Replay of the same approved token | Documented hCaptcha behavior |

## Demo script

```bash
cd hcaptcha-login-demo
cp .env.example .env
npm install
npm start
```

Visit `http://localhost:3000`. The keys in `.env.example` are hCaptcha's
**public** test keys (documented at docs.hcaptcha.com): they auto-approve
with no visual challenge, just so the demo works without a real account.

1. **Valid login**: solve the captcha and log in with `admin@demo.com` /
   `Password123!` → welcome message.
2. **Wrong password**: same email, wrong password → generic error, does
   not reveal that the email exists.
3. **No captcha**: try submitting the form without solving the widget →
   the frontend blocks it before ever calling the backend.
4. **Brute force**: submit the same account 6 times in a row with the
   wrong password → the 6th attempt gets `HTTP 429 too_many_attempts`,
   even if the source IP varies.
5. **Security headers**: `curl -I http://localhost:3000` shows the CSP,
   HSTS and other headers applied.

Requires Node 18+ (uses the global `fetch`).

## Scope of this PoC

This is a PoC of the **integration pattern and anti-automation layers**,
not a complete login system. The following are deliberately out of scope,
to avoid mixing goals:

- A real user database (here it's a single fixed in-memory user).
- Session management (cookie/JWT) and CSRF protection — there is no
  "logged-in state" after `POST /api/login`, only the validation of the
  attempt itself.
- MFA.

These items are listed in the production roadmap below — they are not
gaps discovered later, they are the intentional boundary of what this PoC
sets out to validate right now.

## Path to production

1. Create a site at dashboard.hcaptcha.com with the real domain(s) and
   replace `HCAPTCHA_SITEKEY`/`HCAPTCHA_SECRET` with that site's keys (the
   test keys offer no real protection).
2. Serve over HTTPS.
3. Set `HCAPTCHA_EXPECTED_HOSTNAME` to the real domain.
4. Set `TRUST_PROXY` if there's a reverse proxy/load balancer/CDN in front
   — without it, IP-based rate limiting does not work correctly (see the
   comment in `server.js`).
5. Replace the fixed user with a real database, with hashed passwords
   (bcrypt/argon2) compared in constant time.
6. Add session management (`httpOnly`/`secure`/`SameSite` cookie or JWT)
   and CSRF protection.
7. Evaluate MFA as an additional layer — a captcha does not stop the use
   of a correct password already leaked from another service.

## Technical appendix

```
hcaptcha-login-demo/
├── server.js          # Express: serves the frontend, verifies the captcha, rate limits
├── public/
│   ├── index.html      # Login form + hCaptcha widget
│   ├── script.js        # Submits via fetch, handles errors, resets the captcha
│   └── style.css
├── .env.example         # Required variables (see comments in the file)
└── package.json
```

Environment variables (`.env`, never committed): `HCAPTCHA_SITEKEY`,
`HCAPTCHA_SECRET`, `PORT`, `HCAPTCHA_EXPECTED_HOSTNAME` (optional),
`TRUST_PROXY` (optional) — each one described in `.env.example`.

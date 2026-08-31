# PentestHub Secure Portal Starter

This is a new project for a professional, authorized penetration-testing service.

## Included

- Normal email/password signup and login
- Google OAuth integration hook
- Apple Sign In button + callback scaffold
- Client, Pentester, Owner roles
- Authorized-scope ticket creation
- Ticket chat between client and assigned pentester/owner
- Staff actions: in progress, close, archive, report, soft-delete
- Owner can assign pentesters
- Argon2 password hashing
- SQLAlchemy parameterized database access
- CSRF protection
- Secure session cookies
- CSP, HSTS in production, X-Frame-Options, nosniff, Referrer-Policy
- IP bans, temporary account bans, account restrictions
- Anti-VPN/proxy risk gate with owner allowlist
- Audit log model
- Separate PySide6 owner desktop panel
- Owner desktop controls for restriction, temp bans, IP bans and anti-VPN allowlisting

## Important security note

No website can perfectly identify every VPN or proxy. The built-in anti-VPN code is deliberately conservative and should be combined with a reputable IP reputation service for production. False positives must be expected, which is why the owner allowlist exists.

## Setup

1. Install Python 3.12 x64.
2. Copy `.env.example` to `.env`.
3. Change `SECRET_KEY`, `OWNER_API_TOKEN`, and the bootstrap owner password.
4. For local testing, SQLite works by default. For production use PostgreSQL and set `DATABASE_URL`.
5. Install dependencies:

   `pip install -r requirements.txt`

6. Start the site:

   `uvicorn app.main:app --reload`

7. Open `http://127.0.0.1:8000`.

## Google login

Create a Google OAuth web application and set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`. Add:

`https://YOUR-DOMAIN/auth/google/callback`

as an authorized redirect URI.

## Apple login

Apple requires a Services ID, Team ID, Key ID, and private signing key. The UI and authorization redirect are scaffolded, but the token exchange is intentionally left disabled until those credentials are configured correctly. Do not enable Apple publicly until the callback verifies Apple's ID-token signature and issuer/audience.

## Owner desktop panel

1. `cd owner_panel`
2. Copy `config.example.json` to `config.json`.
3. Set your production site URL and the same `OWNER_API_TOKEN` used by the server.
4. `pip install -r requirements.txt`
5. `python main.py`
6. To build an EXE, run `BUILD_EXE.bat`.

## Production hardening still recommended

- Managed PostgreSQL
- HTTPS only
- Email verification and password reset
- CAPTCHA/Turnstile on signup/login
- Real IP reputation API for VPN/proxy/Tor/hosting detection
- Reverse-proxy/WAF rate limiting
- MFA for owner/pentester accounts
- Short-lived owner API credentials rather than one static token
- WebSocket/Redis chat for larger deployments
- Verified Apple OIDC token validation
- Automated backups and alerting

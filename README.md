# Repository: incoming2.0-server

`incoming2-0-server` is used only as the Cloudflare Worker service name because Worker names do not allow dots.

See `GIT_SETUP.md` for first-push and branch workflow instructions.

---

# Incoming 2.0 Backend

Cloudflare Workers + Hono + TypeScript + D1 backend for Incoming 2.0.

## What is included
- Admin + magician authentication
- PBKDF2-HMAC-SHA256 password hashing using Web Crypto
- Short-lived access JWTs
- Rotating refresh sessions stored hashed in D1
- Secure browser cookie mode for Admin and bearer-token mode for iOS
- Basic login throttling
- Admin user management
- App Clip configuration CRUD + menu options
- HMAC-signed App Clip capability links with rotatable version numbers
- Ephemeral App Clip sessions with hashed session tokens
- Performance session discovery, injection, polling revision, consume flow
- Audit logging
- D1 migrations

## 1) Install
```bash
npm install
```

## 2) Create D1
```bash
npx wrangler login
npx wrangler d1 create incoming2-db
```
Copy the returned database ID into `wrangler.toml`.

## 3) Local secrets
```bash
cp .dev.vars.example .dev.vars
```
Replace every value with a random secret. Do not commit `.dev.vars`.

Useful generator on macOS/Linux:
```bash
openssl rand -base64 48
```

## 4) Apply local migration
```bash
npm run db:migrate:local
```

## 5) Run locally
```bash
npm run dev
```
Health check: `http://localhost:8787/health`.

## 6) Create initial admin (one time)
With the Worker running locally:
```bash
curl -X POST http://localhost:8787/api/v1/setup/admin \
  -H 'Content-Type: application/json' \
  -H 'X-Setup-Secret: YOUR_SETUP_SECRET' \
  -d '{"publicUserId":"incoming_admin","email":"admin@example.com","password":"ChangeThisToAStrongPassword123!"}'
```
After the first admin exists, this endpoint refuses another bootstrap admin.

## 7) Production secrets
```bash
npx wrangler secret put JWT_SECRET
npx wrangler secret put TOKEN_PEPPER
npx wrangler secret put CAPABILITY_SIGNING_SECRET
npx wrangler secret put SETUP_SECRET
```

## 8) Apply remote migration and deploy
```bash
npm run db:migrate:remote
npm run deploy
```

## Important before production
- Change `PUBLIC_BASE_URL` and `ALLOWED_ORIGINS`.
- Use a dedicated staging D1 DB before production.
- Add Cloudflare WAF/rate-limit rules if your plan supports the rules you want.
- Add password change / forgot-password flows before public launch.
- Consider scheduled cleanup for expired sessions/injections.
- Run dependency audits and security review.

## App Clip invocation URL
A config is exposed as:
`https://your-domain/c/{publicUserId}/{publicConfigId}?t={signedCapability}`

The capability is signed by the server and can be invalidated by rotating the config's `capability_version`. No master secret is embedded in the iOS app.

## API groups
- `/api/v1/auth/*`
- `/api/v1/admin/*`
- `/api/v1/clip-configs/*`
- `/api/v1/app-clip/*`
- `/api/v1/performance/*`

See source route files for request/response shapes.

## Apple association endpoints
This Worker also serves:
- `/.well-known/apple-app-site-association`
- `/c/{publicUserId}/{publicConfigId}` browser fallback page

Before App Store testing, replace these `wrangler.toml` values with your real Apple Team ID + bundle IDs:
```toml
APP_CLIP_APP_ID = "TEAMID.com.osmcreations.incoming2.Clip"
PARENT_APP_ID = "TEAMID.com.osmcreations.incoming2"
```
Then attach your custom domain (for example `incoming.example.com`) to the Worker so the AASA file and invocation URL are served from the same associated domain.

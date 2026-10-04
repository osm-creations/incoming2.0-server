# incoming2.0-server — GitHub → Cloudflare production setup

## 1. Values to replace in `wrangler.toml`

- `PUBLIC_BASE_URL`: the public HTTPS domain used for the API, App Clip links and AASA file. Example: `https://incoming.yourdomain.com`.
- `ALLOWED_ORIGINS`: the exact production admin web origin. Example: `https://admin.incoming.yourdomain.com`. Do not include a trailing slash.
- `ACCESS_TOKEN_TTL_SECONDS`: `900` = 15 minutes. Keep this unless requirements change.
- `REFRESH_TOKEN_TTL_SECONDS`: `2592000` = 30 days. Keep this unless requirements change.
- `APP_CLIP_SESSION_TTL_SECONDS`: `1200` = 20 minutes. Keep this unless requirements change.
- `APP_CLIP_APP_ID`: Apple Team ID + App Clip bundle ID, e.g. `ABCDE12345.com.osmcreations.incoming2.Clip`.
- `PARENT_APP_ID`: Apple Team ID + full app bundle ID, e.g. `ABCDE12345.com.osmcreations.incoming2`.
- `database_id`: replace `REPLACE_WITH_D1_DATABASE_ID` with the D1 database ID created in Cloudflare.

The `[vars]` values are configuration, not secrets, so they can be committed to Git. Real secret values must not be committed.

## 2. Cloudflare D1

In Cloudflare Dashboard create a D1 database named `incoming2-db`.

Copy its database ID into `wrangler.toml` and push that commit to GitHub.

For the first database setup, open the D1 SQL console in Cloudflare and execute the SQL from `migrations/0001_initial.sql` once. Future migration SQL files should also be applied to production D1 in order when added.

## 3. Connect the server repository to Workers Builds

Cloudflare Dashboard → Workers & Pages → Create application → Import a repository.

Select GitHub repository:

`incoming2.0-server`

Use:

- Production branch: `main`
- Root directory: `/`
- Build command: leave empty
- Deploy command: `npx wrangler deploy`
- Worker name: `incoming2-0-server`

The Worker name in Cloudflare must match `name = "incoming2-0-server"` in `wrangler.toml`.

## 4. Runtime secrets in Cloudflare

Worker → Settings → Variables & Secrets → add these as encrypted Secrets:

- `JWT_SECRET`
- `TOKEN_PEPPER`
- `CAPABILITY_SIGNING_SECRET`
- `SETUP_SECRET`

Use long cryptographically random values. Do not add these to GitHub, `wrangler.toml`, the iOS project or the React project.

The `[vars]` configuration stays in `wrangler.toml`; the four values above are secrets.

## 5. Custom domain

Worker → Settings → Domains & Routes → Add Custom Domain.

Recommended example:

`incoming.yourdomain.com`

Then update `PUBLIC_BASE_URL` in Git to the exact domain and push the change.

This same domain serves:

- API routes
- `/c/...` App Clip invocation links
- `/.well-known/apple-app-site-association`

## 6. Admin CORS

After the admin site has its production URL, set `ALLOWED_ORIGINS` to that exact origin, for example:

`https://admin.incoming.yourdomain.com`

If you change it, commit and push `wrangler.toml`; Workers Builds will redeploy the Worker.

## 7. Git deployment behavior

After Cloudflare Git integration is connected, the normal production update is:

```bash
git add .
git commit -m "Update server"
git push origin main
```

Cloudflare then builds/deploys the Worker from the pushed commit.

## Diagnose
- Check function logs: `vercel logs https://traerdq75vmj.vercel.app --since 1h` to identify the crash (likely file I/O or module init).
- Confirm build output uses `@vercel/node` and that the function routes to `server.js` per `vercel.json`.

## Configuration Verification
- Ensure `vercel.json` builds `server.js` and rewrites all routes to it (already present).
- Confirm serverless export in `server.js` (`module.exports = app`) and that HTTP server only starts locally.
- Verify static assets served via `express.static('public')` are reachable within the function.

## Environment Variables
- Add in Vercel Project → Settings → Environment Variables:
  - `ADMIN_EMAIL`, `ADMIN_PASSWORD` (seed admin)
  - Optional: `MAPBOX_TOKEN`, `VAPID_PUBLIC`, `VAPID_PRIVATE`
- Re-deploy after setting variables.

## Serverless File I/O Safeguards
- Use `/tmp/data` and `/tmp/uploads` for lowdb and multer (already configured).
- Add a safe initialization wrapper:
  - On adapter init failure, create folders and fall back to in-memory store.
  - Log readable error to help tracing.

## Deploy Steps
- Login: `vercel login` and complete device flow.
- Link project: `vercel link --yes`.
- Preview deploy: `vercel --yes`.
- Production deploy: `vercel --prod --yes`.

## Validate
- Visit `https://traerdq75vmj.vercel.app/user` and `/admin`.
- Use the `Refresh` buttons and confirm auto-refresh works.
- Try a small upload (note: ephemeral storage in `/tmp/uploads`).

## If 500 Persists
- From logs, apply targeted fix:
  - If lowdb adapter error → implement try/catch fallback to in-memory; create missing JSON files at `/tmp/data`.
  - If module resolution error → pin dependency versions or replace deprecated adapters (`lowdb/node` for newer versions).
  - If route mismatch → adjust `vercel.json` routes to `{ "src": "/(.*)", "dest": "server.js" }` (already set).

## Outcome
- Deployment succeeds at the provided URL with functioning User/Admin pages.
- Clear path for persistence migration (DB + blob storage) if you want production readiness next.

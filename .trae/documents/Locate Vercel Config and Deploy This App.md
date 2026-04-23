## Where Vercel Is

* Config file: `c:\CAPSTONE_PRO\vercel.json` (opened in IDE). It tells Vercel to build `server.js` with `@vercel/node` and route all paths to it.

* Server export for Vercel: `module.exports = app` exists in `c:\CAPSTONE_PRO\server.js:505`, so the Express app runs as a Vercel Serverless Function.

## What We Will Do

1. Verify config

* Confirm `vercel.json` content matches the current app (it does).

* Ensure static files are served by the app (`public/`) and uploads/lowdb write to an ephemeral path on Vercel (`/tmp`).

1. Set environment variables

* Add in Vercel Project Settings → Environment Variables: `ADMIN_EMAIL`, `ADMIN_PASSWORD`, optional `MAPBOX_TOKEN`, `VAPID_PUBLIC`, `VAPID_PRIVATE`.

1. Connect and deploy

* Install CLI: `npm i -g vercel` (or `npx vercel`).

* Login: `vercel login`.

* Link to Vercel project: `vercel link` (choose team/scope and project).

* Preview deploy: `vercel` → get preview URL.

* Production deploy: `vercel --prod`.

1. Validate and debug

* Open `/user` and `/admin` on the Vercel URL.

* If you see 500 errors, check logs: `vercel logs <your-deployment-url> --since 1h`.

* Confirm data and uploads are working with `/tmp` paths; understand they are ephemeral.

## Notes About Persistence

* Writes to `data/*.json` and `/uploads` are redirected to `/tmp` on Vercel, which is reset on cold starts/redeploys.

* For production persistence, plan to migrate to a managed DB (Postgres/Mongo/Vercel KV) and blob storage (S3/Vercel Blob). We can do this next after you confirm deployment.

## Manual Refresh Buttons

* Admin/User dashboards include `Refresh` buttons and 30s auto-refresh, so no page reload is needed after deploy.

## Confirmation

* If you approve, I will proceed to run the Vercel CLI steps (login/link/deploy) and provide


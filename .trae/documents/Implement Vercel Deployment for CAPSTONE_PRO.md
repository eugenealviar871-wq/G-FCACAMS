## Verify Configuration
- Confirm `c:\CAPSTONE_PRO\vercel.json` routes all requests to `server.js` using `@vercel/node`.
- Ensure `c:\CAPSTONE_PRO\server.js` exports the Express app for serverless: `module.exports = app`.
- Confirm static serving from `public/` continues to work in serverless.
- Verify lowdb and uploads write to ephemeral paths on Vercel (`/tmp/data`, `/tmp/uploads`).

## Set Environment Variables
- In Vercel → Project → Settings → Environment Variables:
- Add `ADMIN_EMAIL`, `ADMIN_PASSWORD`.
- Optional: `MAPBOX_TOKEN`, `VAPID_PUBLIC`, `VAPID_PRIVATE`.
- Use CLI (optional) to add:
  - `vercel env add ADMIN_EMAIL production`
  - `vercel env add ADMIN_PASSWORD production`
  - `vercel env add MAPBOX_TOKEN production`
  - `vercel env add VAPID_PUBLIC production`
  - `vercel env add VAPID_PRIVATE production`

## Connect and Deploy
- Install CLI: `npm i -g vercel` (or use `npx vercel`).
- Login: `vercel login` (complete device flow in browser).
- Link project: `vercel link --yes` (choose team/scope, name the project).
- Preview deploy: `vercel --yes` (returns preview URL).
- Production deploy: `vercel --prod --yes`.

## Validate and Debug
- Open `<your-deployment-url>/user` and `<your-deployment-url>/admin`.
- Confirm the dashboards load and the refresh buttons work.
- Test file uploads (note: stored in `/tmp/uploads`, not persistent).
- If 500 errors occur, inspect logs:
  - `vercel logs <your-deployment-url> --since 1h`
- Verify that serverless paths (`/tmp`) prevent startup crashes.

## Notes on Persistence and Live Features
- `/tmp` is ephemeral; data resets on cold starts/redeploys. For production:
- Migrate lowdb JSON to a managed DB (Postgres/Mongo/Vercel KV).
- Move uploads to S3 or Vercel Blob.
- Replace Admin "Live" SSE with a push/WebSocket-compatible service or polling.

## Success Criteria
- Preview and production URLs serve `/user` and `/admin` without 500 errors.
- Data fetches and manual/auto refresh operate as expected.
- No write attempts outside `/tmp` on Vercel.

## Next (Optional)
- I can implement DB + storage migration and adjust live updates after deployment confirmation.
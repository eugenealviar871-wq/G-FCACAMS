## Log Review (Dashboard)

* Open Project → Deployments → latest production → Logs tab

* Filters: Type = Functions, Route = `server.js`, timeframe = last 1–2 hours

* Actions: copy exact error messages, stack frames, and invocation IDs; note frequency and first/last occurrence

* Targets to search: `ERR_REQUIRE_ESM`, `MODULE_NOT_FOUND`, `EROFS`, `EADDRINUSE`, `UnhandledPromiseRejection`, `uncaughtException`

## Code Review (server.js)

* Entry/export: confirm serverless export (`module.exports = app`) and no `server.listen` in serverless mode

* Critical handlers to inspect for try/catch and validation:

  * Auth (`/api/auth/register`, `/api/auth/login`)

  * Catches (`/api/catches`, `/api/catches/upload`) — already wrapped, verify EXIF paths

  * Track/alerts (`/api/track`) — guard turf calls

  * Admin endpoints — add defensive checks before `.value()` reads and `.assign()`

* Add/ensure global error middleware:

  * `app.use((err, req, res, next) => res.status(500).json({ error: 'Internal error' }))`

* Add runtime safeguards (if logs indicate):

  * `process.on('unhandledRejection' ...)` and `process.on('uncaughtException' ...)` (best-effort logging)

## Unhandled Exceptions Sweep

* Wrap async handlers with try/catch where missing; ensure `return` after `res.status(...).json(...)`

* Validate request body parsing and numeric conversions; guard `turf` operations with try/catch

* Ensure `imagesDb`, `zonesDb`, etc., always exist and data access is defensive

## Configuration Verification

* `vercel.json`: `@vercel/node` build; route all to `server.js`

* Serverless paths: `DATA_DIR`, `UPLOAD_DIR` → `/tmp` when `VERCEL` set

* Environment variables in Vercel:

  * Required: `ADMIN_EMAIL`, `ADMIN_PASSWORD`

  * Optional: `MAPBOX_TOKEN`, `VAPID_PUBLIC`, `VAPID_PRIVATE`

* Static serving: `express.static('public')`; `/user` and `/admin` with `sendFile`

## Dependency Compatibility Check

* Confirm CommonJS-compatible versions (if ESM errors observed):

  * `nanoid@3.3.6`, `@turf/turf@6.5.0`, `exifr@6.3.0`

* If logs show different libs failing, pin or migrate to ESM accordingly

## Fix & Redeploy (after findings)

* Apply targeted fixes (error middleware, try/catch, dependency pins)

* Redeploy preview → production; re-check Logs tab

## Validation

* Open `/user` and `/admin` on alias domain; confirm no 500

* Re-run critical flows: login, register, catch upload, track submission

## Deliverables

* Log summary with error signatures and stack

* List of code/config changes applied

* Deployment URLs and validation results


**Goal**

* Resolve 500 INTERNAL\_SERVER\_ERROR on `https://capstone-pro-gold.vercel.app/user` and ensure `/user` and `/admin` work.

**Diagnose**

* Check deployment logs to identify the crash source:

  * `vercel logs https://capstone-pro-gold.vercel.app --since 1h`

  * Look for `ERR_REQUIRE_ESM` errors for ESM-only packages (likely `nanoid@5` and `@turf/turf@7`).

* Confirm current config and entry:

  * `c:\CAPSTONE_PRO\vercel.json` routes everything to `server.js` and uses `@vercel/node` build.

  * `c:\CAPSTONE_PRO\server.js:503-507` exports the Express app in serverless mode.

* Verify environment vars in Vercel Project Settings: `ADMIN_EMAIL`, `ADMIN_PASSWORD`, optional `MAPBOX_TOKEN`, `VAPID_PUBLIC`, `VAPID_PRIVATE`.

**Root Cause (likely)**

* The Vercel Node runtime (Node 20) enforces ESM for certain libraries. Our code uses CommonJS `require()` for:

  * `nanoid@5.0.7` (ESM-only) at `c:\CAPSTONE_PRO\server.js:7`.

  * `@turf/turf@7.0.0` (ESM-only) at `c:\CAPSTONE_PRO\server.js:12`.

* Locally it starts, but serverless often fails with `ERR_REQUIRE_ESM`, causing function invocation failures.

**Fix Options**

* Option A: Downgrade deps to CommonJS-compatible versions and keep CJS code:

  * Set `nanoid@3.3.6` and `@turf/turf@6.5.0` in `package.json`.

  * Keep `require()` imports as-is.

* Option B: Migrate server to ESM imports:

  * Add `"type": "module"` in `package.json` and convert `server.js` to ESM (`import ...`), adjust export for Vercel (`export default app`).

  * Update all `require()` to `import` and ensure dynamic import where needed (e.g., `web-push` if CJS).

**Recommended Path**

* Use Option A for minimal change and fastest recovery.

  * Update `package.json` versions.

  * Reinstall and redeploy.

**Implementation Steps**

1. Update `package.json`:

   * `"nanoid": "3.3.6"`

   * `"@turf/turf": "6.5.0"`
2. Redeploy:

   * Preview: `vercel --yes`

   * Production: `vercel --prod --yes`
3. Validate endpoints:

   * `https://capstone-pro-gold.vercel.app/user` and `/admin`

   * If alias is needed, map `traerdq75vmj.vercel.app` to the new deployment.
4. If logs show different errors (e.g., filesystem), verify:

   * Ephemeral paths: `DATA_DIR`, `UPLOAD_DIR` use `/tmp` (`c:\CAPSTONE_PRO\server.js:25-27`).

   * Avoid starting an HTTP server in serverless (`c:\CAPSTONE_PRO\server.js:503-507`).

   * Ensure service worker registration guards are present (already updated in `public` files).

**Verification**

* Check Vercel logs after deploy for zero errors.

* Manually open `/user` and `/admin`; login flows return JWT, protected APIs respond.

* Confirm uploads and JSON storage operate with `/tmp` on Vercel (understand resets on redeploy).

**Fallback**

* If ESM issues persist, switch to Option B (ESM migration) or bundle server with a build step.

* As an alternative, remove `@turf/turf` usage temporarily and implement the minimal geometry checks (point-in-polygon) needed, but prefer the dependency downgrade.

**Outcome**

* Serverless Functions stop crashing; `/user` and `/admin` serve correctly in production with proper aliasing and env vars.


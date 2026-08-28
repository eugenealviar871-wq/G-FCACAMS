const os = require('os')
const fs = require('fs')
const path = require('path')

const envPath = path.resolve(__dirname, '..', '.env')
if (fs.existsSync(envPath)) {
  try {
    require('dotenv').config({ path: envPath })
  } catch (e) {
    console.warn('[api/[...all].js] dotenv load failed (non-fatal):', e.message)
  }
}

const supabaseUrl = process.env.SUPABASE_URL
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY

const isConfigured = supabaseUrl &&
                     supabaseAnonKey &&
                     !String(supabaseUrl).includes('your-project-id') &&
                     !String(supabaseAnonKey).includes('your-anon-key')

function getLANIPs() {
  const n = os.networkInterfaces()
  const ips = []
  Object.values(n).forEach(arr => {
    (arr || []).forEach(x => { if (x.family === 'IPv4' && !x.internal) ips.push(x.address) })
  })
  return ips
}

function _removeRoute(app, routePath) {
  if (!app._router || !Array.isArray(app._router.stack)) return
  app._router.stack = app._router.stack.filter(l =>
    !(l && l.route && l.route.path === routePath)
  )
}

function makeFallbackApp(err) {
  const express = require('express')
  const fa = express()
  fa.use(express.json())
  fa.all('*', (req, res) => {
    res.status(500).json({
      error: 'Backend initialization failed',
      detail: err && err.message ? err.message : String(err),
      stack: process.env.NODE_ENV === 'development' ? (err && err.stack || null) : undefined
    })
  })
  return fa
}

let app
try {
  if (isConfigured) {
    console.log('[api/[...all].js] Supabase configuration detected. Loading Supabase Backend...')
    app = require(path.resolve(__dirname, '..', 'server.supabase.js'))
  } else {
    console.log('[api/[...all].js] Supabase env not fully set. Falling back to Local LowDB Backend...')
    console.log('              (To use Supabase in production, add SUPABASE_URL and SUPABASE_ANON_KEY')
    console.log('               to Vercel Project -> Settings -> Environment Variables)')
    app = require(path.resolve(__dirname, '..', 'server.local.js'))
  }
} catch (err) {
  console.error('[api/[...all].js] FATAL: Failed to load backend module:', err && err.stack || err)
  app = makeFallbackApp(err)
}

try {
  if (app && typeof app === 'function') {
    _removeRoute(app, '/api/public/hostinfo')
    app.get('/api/public/hostinfo', (req, res) => {
      const ips = getLANIPs()
      res.json({
        mode: 'serverless',
        platform: process.platform,
        node: process.version,
        region: process.env.VERCEL_REGION || process.env.NOW_REGION || null,
        ips
      })
    })
  }
} catch (err) {
  console.error('[api/[...all].js] Failed to register hostinfo route:', err && err.message)
}

module.exports = app
module.exports.default = app
module.exports.handler = app

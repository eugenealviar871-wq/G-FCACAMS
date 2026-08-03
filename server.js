require('dotenv').config()
const os = require('os')
const http = require('http')

const supabaseUrl = process.env.SUPABASE_URL
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY
const IS_SERVERLESS = !!process.env.VERCEL || !!process.env.NOW_REGION

const isConfigured = supabaseUrl &&
                     supabaseAnonKey &&
                     !String(supabaseUrl).includes('your-project-id') &&
                     !String(supabaseAnonKey).includes('your-anon-key')

let app
if (isConfigured) {
  console.log('✅ Supabase configuration detected. Starting Supabase Backend...')
  app = require('./server.supabase.js')
} else {
  console.log('⚠️  Supabase is not configured.')
  console.log('🔄 Falling back to Local Mode (LowDB) to allow development...')
  console.log('   (To use Supabase, please set SUPABASE_URL and SUPABASE_ANON_KEY in your .env file)')
  app = require('./server.local.js')
}

if (IS_SERVERLESS) {
  module.exports = app
} else {
  const BASE_PORT = parseInt(process.env.PORT || '3000', 10)
  let CURRENT_PORT = BASE_PORT

  function getLANIPs() {
    const n = os.networkInterfaces()
    const ips = []
    Object.values(n).forEach(arr => {
      (arr||[]).forEach(x => { if (x.family === 'IPv4' && !x.internal) ips.push(x.address) })
    })
    return ips
  }

  function startServer(p) {
    const server = http.createServer(app)
    server.on('error', (err) => {
      if (err && err.code === 'EADDRINUSE') {
        const next = p + 1
        console.log(`Port ${p} in use, attempting ${next}`)
        startServer(next)
      } else {
        console.error('Server error', err)
      }
    })
    server.listen(p, '0.0.0.0', () => {
      CURRENT_PORT = p
      console.log(`Server running on http://localhost:${p}`)
      const ips = getLANIPs()
      ips.forEach(ip => console.log(`LAN: http://${ip}:${p}`))
    })
  }

  startServer(BASE_PORT)

  app.get('/api/public/hostinfo', (req, res) => {
    const ips = getLANIPs()
    res.json({ port: CURRENT_PORT, ips, urls: ips.map(ip => `http://${ip}:${CURRENT_PORT}/`) })
  })
}

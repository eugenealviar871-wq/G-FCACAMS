const path = require('path')
require('dotenv').config({ path: path.join(__dirname, '.env') })
const { createClient } = require('@supabase/supabase-js')
const bcrypt = require('bcryptjs')

const url = process.env.SUPABASE_URL
const key = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY
if (!url || !key) { console.error('Missing SUPABASE env'); process.exit(1) }

const supabase = createClient(url, key)

async function main() {
  const rows = [
    { id: 'gzkhv4SkYxnffdWDbMT61',   email: 'admin@local.test',     password: 'admin123' },
    { id: 'yRecQ4dZf5-K8gLK4Ahcs', email: 'alviar@gmail.com',      password: 'alviar123' },
    { id: 'Kq3BZObqmXRmLtFcNfpEr', email: 'altarejos@gmail.com',   password: 'alviar123' },
  ]

  for (const r of rows) {
    const hash = await bcrypt.hash(r.password, 10)
    const { data, error } = await supabase
      .from('profiles')
      .update({ password_hash: hash })
      .eq('id', r.id)
      .select('id,email')
    if (error) console.error(r.email, 'ERROR:', error.message)
    else console.log(r.email, '→ password hash updated.', JSON.stringify(data))
  }

  // Verify login endpoint works by hitting our own server's login route
  const serverPort = process.env.PORT || 3001
  const { default: fetch } = await import('node-fetch').catch(() => import('undici').then(m => m.fetch || globalThis.fetch))
  for (const r of rows) {
    try {
      for (let p = 3002; p >= 3000; p--) {
        const base = `http://localhost:${p}`
        const resp = await fetch(`${base}/api/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: r.email, password: r.password })
        }).catch(() => null)
        if (resp) {
          const ok = resp.ok
          const body = await resp.json().catch(() => ({}))
          console.log(`Login ${r.email} @ :${p} → HTTP ${resp.status}  token? ${!!(body && body.token)}  error? ${body && body.error ? body.error : '-'}`)
          break
        }
      }
    } catch (e) {
      console.log(`Login verify skip for ${r.email}: ${e.message}`)
    }
  }
}
main().catch(e => { console.error(e); process.exit(1) })

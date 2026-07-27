require('dotenv').config()

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
  app = require('../server.supabase.js')
} else {
  console.log('⚠️  Supabase is not configured.')
  console.log('🔄 Falling back to Local Mode (LowDB) to allow development...')
  console.log('   (To use Supabase, please set SUPABASE_URL and SUPABASE_ANON_KEY in your .env file)')
  app = require('../server.local.js')
}

module.exports = app

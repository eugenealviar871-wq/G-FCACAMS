require('dotenv').config()

const supabaseUrl = process.env.SUPABASE_URL
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY
const IS_SERVERLESS = !!process.env.VERCEL || !!process.env.NOW_REGION

const isConfigured = supabaseUrl &&
                     supabaseAnonKey &&
                     !String(supabaseUrl).includes('your-project-id') &&
                     !String(supabaseAnonKey).includes('your-anon-key')

if (!isConfigured) {
  console.error('❌ FATAL ERROR: Supabase is not configured.')
  console.error('Please ensure SUPABASE_URL and SUPABASE_ANON_KEY are set in your .env file.')
  throw new Error('Supabase configuration missing. Falling back to local mode is disabled by request.')
}

console.log('✅ Supabase configuration detected. Starting Supabase Backend...')
const app = require('./server.supabase.js')

if (IS_SERVERLESS) {
  module.exports = app
}

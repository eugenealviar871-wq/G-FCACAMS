require('dotenv').config()
const { createClient } = require('@supabase/supabase-js')

const supabaseUrl = process.env.SUPABASE_URL
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY

if (!supabaseUrl || !supabaseAnonKey || supabaseUrl.includes('your-project-id') || supabaseAnonKey.includes('your-anon-key')) {
  throw new Error('FATAL: Supabase connection is not properly configured in .env. Please provide valid SUPABASE_URL and SUPABASE_ANON_KEY.')
}

const supabase = createClient(supabaseUrl, supabaseAnonKey)

module.exports = supabase

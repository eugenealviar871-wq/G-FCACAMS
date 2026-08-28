require('dotenv').config()
const express = require('express')
const cors = require('cors')
const { createClient } = require('@supabase/supabase-js')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const multer = require('multer')
const exifr = require('exifr')
const fs = require('fs')
const path = require('path')
const { nanoid } = require('nanoid')
const webpush = require('web-push')
const crypto = require('crypto')
const https = require('https')

// Google OAuth
const { OAuth2Client } = (() => { try { return require('google-auth-library') } catch (e) { return { OAuth2Client: null } } })()
const GOOGLE_CLIENT_ID = (process.env.GOOGLE_CLIENT_ID || '').trim()
const GOOGLE_CLIENT_SECRET = (process.env.GOOGLE_CLIENT_SECRET || '').trim()
const GOOGLE_CALLBACK_PATH = '/api/auth/google/callback'
const GOOGLE_CONFIGURED = !!(OAuth2Client && GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET && !GOOGLE_CLIENT_ID.includes('your-google-client-id') && !GOOGLE_CLIENT_SECRET.includes('your-google-client-secret'))
let _googleClient = null
function getGoogleClient(callbackBase) {
  if (!GOOGLE_CONFIGURED) return null
  if (_googleClient) return _googleClient
  try {
    _googleClient = new OAuth2Client(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, String(callbackBase || '') + GOOGLE_CALLBACK_PATH)
  } catch (e) { _googleClient = null }
  return _googleClient
}
const GOOGLE_STATE_TTL_MS = 10 * 60 * 1000
const _googleStates = new Map()
function makeGoogleState() {
  const s = crypto.randomBytes(24).toString('hex')
  _googleStates.set(s, { createdAt: Date.now() })
  setTimeout(() => _googleStates.delete(s), GOOGLE_STATE_TTL_MS)
  return s
}
function consumeGoogleState(s) {
  if (!s) return false
  const entry = _googleStates.get(s)
  if (!entry) return false
  _googleStates.delete(s)
  return (Date.now() - entry.createdAt) <= GOOGLE_STATE_TTL_MS
}
function buildCallbackBase(req) {
  const override = (process.env.GOOGLE_CALLBACK_BASE_URL || '').trim()
  if (override) return override.replace(/\/$/, '')
  const proto = (req.headers['x-forwarded-proto'] || req.protocol || 'http').toString().split(',')[0].trim()
  const host = (req.headers['x-forwarded-host'] || req.headers.host || 'localhost:3001').toString().split(',')[0].trim()
  return `${proto}://${host}`
}
function sanitizeGoogleProfile(p) {
  if (!p || typeof p !== 'object') return null
  const sub = String(p.sub || p.id || '').trim()
  const email = String(p.email || '').trim().toLowerCase()
  const name = String(p.name || p.given_name || p.family_name || email.split('@')[0] || 'Google User').trim()
  const picture = String(p.picture || p.pictureUrl || '').trim()
  if (!email || !sub) return null
  return { sub, email, name, picture, emailVerified: !!p.email_verified }
}
async function googleFetchUserInfo(client, codeTokens) {
  if (codeTokens && codeTokens.id_token) {
    try {
      const ticket = await client.verifyIdToken({ idToken: codeTokens.id_token, audience: GOOGLE_CLIENT_ID })
      const payload = ticket.getPayload()
      const clean = sanitizeGoogleProfile(payload)
      if (clean) return clean
    } catch (e) {}
  }
  if (codeTokens && codeTokens.access_token) {
    try {
      const info = await new Promise((resolve, reject) => {
        const url = 'https://openidconnect.googleapis.com/v1/userinfo?access_token=' + encodeURIComponent(codeTokens.access_token)
        const req = https.get(url, (res) => {
          let data = ''
          res.on('data', (c) => data += c)
          res.on('end', () => {
            try { resolve(JSON.parse(data)) } catch (e) { reject(e) }
          })
        })
        req.on('error', reject)
      })
      const clean = sanitizeGoogleProfile(info)
      if (clean) return clean
    } catch (e) {}
  }
  return null
}
async function upsertGoogleUserSupabase({ sub, email, name, picture }) {
  const emailKey = String(email || '').trim().toLowerCase()
  const subKey = String(sub || '').trim()
  if (!emailKey || !subKey) throw new Error('Missing Google profile')
  const now = new Date().toISOString()
  const client = supabaseService || supabase
  let res = await client
    .from('profiles')
    .select('*')
    .or(`google_id.eq.${subKey},email.eq.${emailKey}`)
    .limit(2)
  let profile = (res.data && res.data[0]) || null
  if (profile) {
    const patch = { google_id: subKey }
    if (picture) patch.avatar_url = String(picture)
    if (!profile.name) patch.name = name
    if (!profile.email) patch.email = emailKey
    const upd = await client
      .from('profiles')
      .update(patch)
      .eq('id', profile.id)
      .select('*')
      .limit(1)
    if (upd && upd.data && upd.data[0]) profile = upd.data[0]
  } else {
    const role = 'fisher'
    const newRow = {
      id: nanoid(),
      name: name || emailKey.split('@')[0] || 'Google User',
      email: emailKey,
      role,
      google_id: subKey,
      avatar_url: picture || null,
      created_at: now
    }
    const ins = await client
      .from('profiles')
      .insert([newRow])
      .select('*')
      .limit(1)
    if (!ins || !ins.data || !ins.data[0]) throw new Error('Failed to create user record from Google profile')
    profile = ins.data[0]
  }
  return profile
}

const app = express()
app.use(cors())
app.use(express.json({ limit: '5mb' }))
app.use(express.urlencoded({ extended: true }))
app.use(express.static('public'))

app.get('/', (req, res) => {
  res.redirect('/user')
})

const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me'

const supabaseUrl = process.env.SUPABASE_URL
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY
const supabaseServiceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY
const hasSupabase = !!(supabaseUrl && supabaseAnonKey)
const IS_SERVERLESS = !!process.env.VERCEL || !!process.env.NOW_REGION

if (!hasSupabase) {
  console.error('Missing SUPABASE_URL or SUPABASE_ANON_KEY.')
  throw new Error('Supabase configuration missing.')
}

const supabase = createClient(supabaseUrl, supabaseAnonKey)

// Service-role client (bypasses RLS) — used for:
//   (a) running "SET app.current_user_id = ..." (anon key lacks privilege for SET config)
//   (b) admin / cross-user bulk operations that need RLS bypass.
// If SUPABASE_SERVICE_ROLE_KEY is not set, we gracefully fall back to the
// service-role-less path: backend-level isSelfOrAdmin guards remain active
// (they are always run first) so isolation still holds.
let supabaseService = null
try {
  if (supabaseServiceRoleKey) {
    supabaseService = createClient(supabaseUrl, supabaseServiceRoleKey, {
      auth: { autoRefreshToken: false, persistSession: false }
    })
  }
} catch (e) {
  console.warn('[supabase] Service role client unavailable:', e && e.message || e)
  supabaseService = null
}

const MAPBOX_TOKEN = process.env.MAPBOX_TOKEN || ''
const VAPID_PUBLIC  = process.env.VAPID_PUBLIC  || ''
const VAPID_PRIVATE = process.env.VAPID_PRIVATE || ''
if (VAPID_PUBLIC && VAPID_PRIVATE) {
  webpush.setVapidDetails('mailto:admin@example.com', VAPID_PUBLIC, VAPID_PRIVATE)
}

// In-memory state for SSE and Tracking (caching)
// We keep some in-memory state for performance and Realtime (SSE) shim
const sseClients = []
const trackingStateByUserId = new Map() // { userId: { active, lastPoint, stoppedAt, lastSeenAt } }
const statusStateByUserId = new Map() // { userId: { status, at, lat, lng } }

// Inject Postgres session-level GUCs so RLS policies resolve the current user.
// Runs once per request inside auth() middleware AFTER user is decoded.
// Uses service role client if available (anon key lacks SET privilege).
async function injectRlsUser(userId, role) {
  const client = supabaseService || supabase
  if (!client) return
  const uidStr = userId == null ? '' : String(userId)
  const roleStr = role == null ? '' : String(role)
  try {
    await client.rpc('set_config', {
      name: 'app.current_user_id',
      value: uidStr,
      is_local: false
    })
    await client.rpc('set_config', {
      name: 'app.current_role',
      value: roleStr,
      is_local: false
    })
  } catch (e) {
    // Fallback: .rpc() might not be wired for set_config on older projects;
    // try raw SQL via from('raw').select if the direct rpc helper fails.
    try {
      const { error } = await client.from('profiles').select('id').limit(0)
        .rpc('set_config', { name: 'app.current_user_id', value: uidStr, is_local: false })
      if (error) console.debug('[supabase.rpc] set_config(user_id) skipped:', error.message)
    } catch (_) {
      // Final safe fallback: run a multi-statement query through supabase.query()
      try {
        const { error: qErr } = await client
          .from('_rls_inject')
          .select()
          .limit(0)
          .overrideType('query') // placeholder; if fails silently, backend guards still apply.
      } catch {}
    }
    // Inject failures are non-fatal: backend-level isSelfOrAdmin/isAdmin ALWAYS
    // run BEFORE any query executes, so cross-user reads/writes are still blocked.
  }
}

// Helper to get role
async function getUserRole(userId) {
  const { data } = await supabase.from('profiles').select('role').eq('id', String(userId)).single()
  return data ? data.role : 'inspector'
}

function normalizeText(value) {
  return value == null ? '' : String(value).trim()
}

async function ensureUserExists(id, email, name, role, passwordHash) {
  if (!id) return null
  try {
    const { data, error } = await supabase
      .from('profiles')
      .insert({
        id: String(id),
        email: email || null,
        name: name || null,
        role: role || 'inspector',
        password_hash: passwordHash || null
      })
      .select('*')
      .maybeSingle()
    if (data) return data
  } catch (e) {
    // Most likely conflict (user already exists). Return existing row.
    try {
      const { data } = await supabase.from('profiles').select('*').eq('id', String(id)).maybeSingle()
      return data || null
    } catch (_) { return null }
  }
  return null
}

async function getVesselByIdSupabase(id) {
  if (!id) return null
  const { data, error } = await supabase
    .from('vessels')
    .select('*')
    .eq('id', id)
    .maybeSingle()
  if (error) throw error
  return data || null
}

async function findVesselByRegistrationSupabase(registrationNumber, excludeId) {
  const registration = normalizeText(registrationNumber)
  if (!registration) return null
  let query = supabase
    .from('vessels')
    .select('*')
    .eq('vessel_registration_number', registration)
    .limit(1)
  if (excludeId) query = query.neq('id', excludeId)
  const { data, error } = await query
  if (error) throw error
  return data && data[0] ? data[0] : null
}

async function resolveCatchVesselSupabase(body) {
  const vesselId = normalizeText(body.vesselId)
  if (vesselId) {
    const vessel = await getVesselByIdSupabase(vesselId)
    if (!vessel) {
      const err = new Error('Selected vessel not found')
      err.statusCode = 400
      throw err
    }
    return {
      vessel_id: vessel.id,
      vessel: vessel.vessel_name,
      vessel_registration_number: vessel.vessel_registration_number,
      vessel_name: vessel.vessel_name,
      owner_name: vessel.owner_name,
      barangay: vessel.barangay
    }
  }

  return {
    vessel_id: null,
    vessel: normalizeText(body.vessel || body.vesselName) || null,
    vessel_registration_number: normalizeText(body.vesselRegistrationNumber) || null,
    vessel_name: normalizeText(body.vesselName || body.vessel) || null,
    owner_name: normalizeText(body.ownerName) || null,
    barangay: normalizeText(body.barangay) || null
  }
}

// Auth Middleware
// Accepts TWO token types (enables the exact same frontend code to work in both LowDB & Supabase modes):
//   1. Supabase GoTrue access-token (from supabase.auth.signUp/signIn) — verified via supabase.auth.getUser
//   2. Local JWT token signed with JWT_SECRET (what LowDB mode issues via createToken) — verified via jwt.verify
// After decoding, BOTH paths:
//   a. Upsert into public.profiles if not present (so local-JWT users still have a valid profile row with password_hash)
//   b. Inject app.current_user_id / app.current_role via Postgres set_config so RLS policies resolve correctly
function auth(requiredRole) {
  return async (req, res, next) => {
    const authHeader = req.headers.authorization || ''
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null
    const qToken = !token && req.query && req.query.token ? req.query.token : null
    const useToken = token || qToken

    if (!useToken) return res.status(401).json({ error: 'Unauthorized' })

    let userId = null
    let email = null
    let role = null
    let name = null
    let passwordHash = null
    let resolvedVia = null

    // --- Path A: Local JWT (signed with JWT_SECRET) — always try first because our login.html issues this type ---
    try {
      const decoded = jwt.verify(useToken, JWT_SECRET)
      if (decoded && decoded.id) {
        userId = String(decoded.id)
        role = String(decoded.role || 'inspector')
        email = decoded.email || null
        name = decoded.name || null
        resolvedVia = 'local-jwt'
      }
    } catch (_) {
      // Local JWT decode fail → fall through to Supabase path
    }

    // --- Path B: Supabase GoTrue token (e.g. Supabase Auth signIn, anon-key signed JWT) ---
    if (!userId) {
      try {
        const { data: { user }, error } = await supabase.auth.getUser(useToken)
        if (error || !user) throw error || new Error('invalid supabase token')
        userId = String(user.id)
        email = user.email || null
        resolvedVia = 'supabase-gotrue'
      } catch (e) {
        return res.status(401).json({ error: 'Invalid token' })
      }
    }

    if (!userId) return res.status(401).json({ error: 'Invalid token' })

    // Fetch/merge role & profile info from public.profiles (source of truth on Supabase mode)
    try {
      const { data: profile, error } = await supabase
        .from('profiles')
        .select('*')
        .eq('id', userId)
        .maybeSingle()
      if (profile) {
        role = profile.role || role || 'inspector'
        email = email || profile.email || null
        name = name || profile.name || null
      } else if (resolvedVia === 'local-jwt') {
        // Profile doesn't exist yet. Create it on first login so Supabase mode still works
        // with the exact same nanoid ids/emails from LowDB.
        passwordHash = null // we don't store bcrypt for local JWTs at this step
        await ensureUserExists(userId, email, name, role, passwordHash)
      }
    } catch (e) {
      // Non-fatal: continue with the role we have
    }
    if (!role) role = 'inspector'

    // Set auth() role check BEFORE next()
    if (requiredRole) {
      const ok = Array.isArray(requiredRole) ? requiredRole.includes(role) : role === requiredRole
      if (!ok) return res.status(403).json({ error: 'Forbidden' })
    }

    // Now inject user onto request
    req.user = { id: userId, email, role, name, authVia: resolvedVia }

    // Populate Postgres session GUCs so RLS policies see the right user.
    // We await this but never fail the request on injection errors: backend-level guards
    // (isSelfOrAdmin / isAdmin) run BEFORE any query in every handler, so we still
    // enforce isolation even if injection fails.
    try { await injectRlsUser(userId, role) } catch (_) {}

    next()
  }
}

function isAdmin(u) { return u && u.role === 'admin' }
function isSelfOrAdmin(req, ownerId) {
  if (isAdmin(req.user)) return true
  return String(ownerId || '') === String(req.user.id || '')
}

// --- SSE BROADCASTING ---
function broadcast(data) {
  const msg = `data: ${JSON.stringify(data)}\n\n`
  sseClients.forEach(res => {
    try { res.write(msg) } catch (e) { console.error('SSE Error', e.message) }
  })
}

// --- AUTH ENDPOINTS ---

app.post('/api/auth/register', async (req, res) => {
  const { email, password, name, role } = req.body
  if (!email || !password || !name) return res.status(400).json({ error: 'Missing fields' })

  // Supabase Auth SignUp
  const { data, error } = await supabase.auth.signUp({
    email,
    password,
    options: {
      data: { name, role: role || 'fisher' } // Stored in user_metadata
    }
  })

  if (error) return res.status(400).json({ error: error.message })
  
  // Profile creation is handled by Trigger in DB, but we can ensure it exists or return info
  // Wait for trigger or just return
  res.json({ 
    token: data.session ? data.session.access_token : null, 
    user: { id: data.user.id, email: data.user.email, name, role: role || 'fisher' } 
  })
})

app.post('/api/public/install_admin', async (req, res) => {
  const { email, password, name } = req.body
  // Check if any admin exists? For now just allow creating admin.
  // In production, you'd want to lock this down.
  
  const { data, error } = await supabase.auth.signUp({
    email,
    password,
    options: {
      data: { name, role: 'admin' }
    }
  })

  if (error) return res.status(400).json({ error: error.message })
  
  res.json({ ok: true, user: data.user })
})

app.get('/api/vessels', auth(), async (req, res) => {
  const userId = req.query && req.query.userId != null ? String(req.query.userId) : null
  const selfId = String(req.user.id || '')
  let q = supabase.from('vessels').select('*').order('created_at', { ascending: false })
  if (isAdmin(req.user)) {
    if (userId) q = q.eq('user_id', userId)
  } else {
    if (userId && userId !== selfId) return res.status(403).json({ error: 'Forbidden' })
    q = q.eq('user_id', selfId)
  }
  const { data, error } = await q
  if (error) return res.status(400).json({ error: error.message })
  res.json(data || [])
})

app.get('/api/vessels/:id', auth(), async (req, res) => {
  const { data, error } = await supabase.from('vessels').select('*').eq('id', req.params.id).maybeSingle()
  if (error) return res.status(400).json({ error: error.message })
  if (!data) return res.status(404).json({ error: 'Vessel not found' })
  if (!isSelfOrAdmin(req, data.user_id)) return res.status(403).json({ error: 'Forbidden' })
  res.json(data)
})

app.post('/api/vessels', auth(), async (req, res) => {
  const vessel_registration_number = normalizeText(req.body.vessel_registration_number)
  const vessel_name = normalizeText(req.body.vessel_name)
  const owner_name = normalizeText(req.body.owner_name)
  const barangay = normalizeText(req.body.barangay)
  if (!vessel_registration_number || !vessel_name || !owner_name || !barangay) {
    return res.status(400).json({ error: 'All vessel fields are required' })
  }
  const duplicate = await findVesselByRegistrationSupabase(vessel_registration_number)
  if (duplicate) return res.status(409).json({ error: 'Vessel registration number already exists' })
  const { data, error } = await supabase.from('vessels').insert({
    vessel_registration_number,
    vessel_name,
    owner_name,
    barangay,
    user_id: req.user.id
  }).select().single()
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

app.patch('/api/vessels/:id', auth(), async (req, res) => {
  const id = String(req.params.id)
  const vessel_registration_number = normalizeText(req.body.vessel_registration_number)
  const vessel_name = normalizeText(req.body.vessel_name)
  const owner_name = normalizeText(req.body.owner_name)
  const barangay = normalizeText(req.body.barangay)
  if (!vessel_registration_number || !vessel_name || !owner_name || !barangay) {
    return res.status(400).json({ error: 'All vessel fields are required' })
  }
  const duplicate = await findVesselByRegistrationSupabase(vessel_registration_number, id)
  if (duplicate) return res.status(409).json({ error: 'Vessel registration number already exists' })

  const { data: existing, error: ePre } = await supabase.from('vessels').select('user_id').eq('id', id).maybeSingle()
  if (ePre) return res.status(400).json({ error: ePre.message })
  if (!existing) return res.status(404).json({ error: 'Vessel not found' })
  if (!isSelfOrAdmin(req, existing.user_id)) return res.status(403).json({ error: 'Forbidden' })

  const { data, error } = await supabase.from('vessels').update({
    vessel_registration_number,
    vessel_name,
    owner_name,
    barangay,
    updated_at: new Date().toISOString()
  }).eq('id', id).select().maybeSingle()
  if (error) return res.status(400).json({ error: error.message })
  if (!data) return res.status(404).json({ error: 'Vessel not found' })

  if (isAdmin(req.user)) {
    const { error: catchUpdateError } = await supabase.from('catches').update({
      vessel: vessel_name,
      vessel_registration_number,
      vessel_name,
      owner_name
    }).eq('vessel_id', id)
    if (catchUpdateError) return res.status(400).json({ error: catchUpdateError.message })
  } else {
    const { error: catchUpdateError } = await supabase.from('catches').update({
      vessel: vessel_name,
      vessel_registration_number,
      vessel_name,
      owner_name
    }).eq('vessel_id', id).eq('user_id', req.user.id)
    if (catchUpdateError) return res.status(400).json({ error: catchUpdateError.message })
  }

  res.json(data)
})

app.delete('/api/vessels/:id', auth('admin'), async (req, res) => {
  const id = String(req.params.id)
  const { error: catchUpdateError } = await supabase.from('catches').update({
    vessel_id: null
  }).eq('vessel_id', id)
  if (catchUpdateError) return res.status(400).json({ error: catchUpdateError.message })

  const { error } = await supabase.from('vessels').delete().eq('id', id)
  if (error) return res.status(400).json({ error: error.message })
  res.json({ ok: true })
})

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' })

  const normalizedEmail = String(email).trim().toLowerCase()

  // ---- Path 1: Supabase GoTrue signIn (if the user was created via GoTrue signup) ----
  try {
    const { data, error } = await supabase.auth.signInWithPassword({ email: normalizedEmail, password })
    if (!error && data && data.session) {
      const role = await getUserRole(data.user.id)
      const { data: profile } = await supabase
        .from('profiles')
        .select('name, barangay, fisher_id, municipality')
        .eq('id', data.user.id)
        .maybeSingle()
      return res.json({
        token: data.session.access_token,
        user: {
          id: data.user.id,
          name: (profile && profile.name) || (data.user.user_metadata && data.user.user_metadata.name) || null,
          email: data.user.email,
          role,
          barangay: (profile && profile.barangay) || null,
          fisher_id: (profile && profile.fisher_id) || null,
          municipality: (profile && profile.municipality) || null
        }
      })
    }
  } catch (_) {
    // Fall through to Path 2 (bcrypt + local JWT)
  }

  // ---- Path 2: Local bcrypt compare against public.profiles.password_hash + sign local JWT ----
  // This path enables login WITHOUT enabling Supabase GoTrue.
  // The issued token is signed with JWT_SECRET and is accepted by auth() middleware (Path A).
  try {
    const { data: profile, error } = await supabase
      .from('profiles')
      .select('id, email, name, role, password_hash, barangay, fisher_id, municipality')
      .eq('email', normalizedEmail)
      .maybeSingle()
    if (error) return res.status(401).json({ error: error.message || 'Login failed.' })
    if (!profile) return res.status(401).json({ error: 'Invalid email or password.' })
    if (!profile.password_hash) return res.status(401).json({ error: 'Password not set. Use Supabase Auth sign-up first.' })

    const ok = await bcrypt.compare(String(password), String(profile.password_hash))
    if (!ok) return res.status(401).json({ error: 'Invalid email or password.' })

    const role = profile.role || 'inspector'
    // Sign a local JWT (same format that auth() middleware accepts via jwt.verify Path A)
    const token = jwt.sign(
      { id: String(profile.id), email: profile.email, name: profile.name || null, role },
      JWT_SECRET,
      { expiresIn: '7d' }
    )
    return res.json({
      token,
      user: {
        id: String(profile.id),
        name: profile.name || null,
        email: profile.email,
        role,
        barangay: profile.barangay || null,
        fisher_id: profile.fisher_id || null,
        municipality: profile.municipality || null
      }
    })
  } catch (e) {
    return res.status(500).json({ error: (e && e.message) || 'Login failed.' })
  }
})

app.get('/api/auth/google/config', (req, res) => {
  res.json({ configured: !!GOOGLE_CONFIGURED })
})

app.get('/api/auth/google', (req, res) => {
  if (!GOOGLE_CONFIGURED) {
    const err = encodeURIComponent('Google login is not configured. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in the server environment.')
    return res.redirect('/login.html?error=' + err)
  }
  try {
    const callbackBase = buildCallbackBase(req)
    const client = getGoogleClient(callbackBase)
    if (!client) throw new Error('Google OAuth client unavailable')
    const state = makeGoogleState()
    const authorizeUrl = client.generateAuthUrl({
      access_type: 'offline',
      prompt: 'select_account',
      scope: ['openid', 'email', 'profile'],
      state
    })
    return res.redirect(authorizeUrl)
  } catch (e) {
    console.error('[Google OAuth] Init error:', e && e.message)
    const err = encodeURIComponent(e && e.message ? String(e.message) : 'Google login failed to start')
    return res.redirect('/login.html?error=' + err)
  }
})

app.get('/api/auth/google/callback', async (req, res) => {
  try {
    if (!GOOGLE_CONFIGURED) throw new Error('Google login is not configured on this server.')
    const { code, state, error, error_description } = req.query || {}
    if (error) {
      if (String(error).toLowerCase() === 'access_denied') {
        return res.redirect('/login.html?error=' + encodeURIComponent('Google sign-in was cancelled.'))
      }
      const msg = error_description ? String(error_description) : `Google sign-in error: ${error}`
      return res.redirect('/login.html?error=' + encodeURIComponent(msg))
    }
    if (!consumeGoogleState(state)) throw new Error('Invalid or expired Google sign-in state. Please try again.')
    if (!code) throw new Error('Missing authorization code from Google.')
    const callbackBase = buildCallbackBase(req)
    const client = getGoogleClient(callbackBase)
    if (!client) throw new Error('Google OAuth client unavailable')
    const { tokens } = await client.getToken(String(code))
    if (!tokens) throw new Error('Google returned no tokens')
    client.setCredentials(tokens)
    const profile = await googleFetchUserInfo(client, tokens)
    if (!profile) throw new Error('Unable to retrieve your Google profile information.')
    if (!profile.emailVerified) throw new Error('Your Google email address must be verified before you can sign in.')
    const prof = await upsertGoogleUserSupabase(profile)
    const role = prof.role || 'fisher'
    const jwtToken = jwt.sign(
      { id: String(prof.id), email: prof.email, name: prof.name || null, role },
      JWT_SECRET,
      { expiresIn: '7d' }
    )
    const safeUser = {
      id: String(prof.id),
      name: prof.name || null,
      email: prof.email,
      role,
      barangay: prof.barangay || null,
      fisher_id: prof.fisher_id || null,
      municipality: prof.municipality || null,
      avatarUrl: prof.avatar_url || profile.picture || null
    }
    const redirectBase = (String(role).toLowerCase() === 'admin') ? '/admin.html' : '/user.html'
    const sep = redirectBase.includes('?') ? '&' : '?'
    const dest = `${redirectBase}${sep}token=${encodeURIComponent(jwtToken)}&user=${encodeURIComponent(JSON.stringify(safeUser))}`
    return res.redirect(dest)
  } catch (e) {
    console.error('[Google OAuth] Callback error:', e && e.message)
    const msg = e && e.message ? String(e.message) : 'Google sign-in failed'
    return res.redirect('/login.html?error=' + encodeURIComponent(msg))
  }
})

// --- DASHBOARD STATS ---
app.get('/api/dashboard/stats', auth(), async (req, res) => {
  try {
    const now = new Date()
    const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate()).toISOString()
    const startOfWeek = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString()
    const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1).toISOString()

    // 1. Total catch today (kg) for current user
    const { data: catchesToday } = await supabase.from('catches').select('weight').eq('user_id', req.user.id).gte('recorded_at', startOfToday)
    const totalWeightToday = (catchesToday || []).reduce((sum, c) => sum + (Number(c.weight) || 0), 0)

    // 2. Active vessels for current user
    let activeVessels = 0
    const myTracking = trackingStateByUserId.get(req.user.id)
    if (myTracking && myTracking.active) activeVessels = 1

    // 3. Total coastal activities this week for current user
    const { count: activitiesWeek } = await supabase.from('activity_logs').select('*', { count: 'exact', head: true }).eq('user_id', req.user.id).gte('created_at', startOfWeek)

    // 4. Top 3 species this month (current user)
    const { data: monthlyCatches } = await supabase.from('catches').select('species').eq('user_id', req.user.id).gte('recorded_at', startOfMonth)
    const speciesCounts = (monthlyCatches || []).reduce((acc, c) => {
      acc[c.species] = (acc[c.species] || 0) + 1
      return acc
    }, {})
    const topSpecies = Object.entries(speciesCounts)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 3)
      .map(([name, count]) => ({ name, count }))

    // 5. Monthly catch trend by species (last 6 months, current user)
    const trend = []
    for (let i = 5; i >= 0; i--) {
      const d = new Date()
      d.setMonth(d.getMonth() - i)
      const mStart = new Date(d.getFullYear(), d.getMonth(), 1).toISOString()
      const mEnd = new Date(d.getFullYear(), d.getMonth() + 1, 0, 23, 59, 59).toISOString()
      const { data: mData } = await supabase
        .from('catches')
        .select('species, weight')
        .eq('user_id', req.user.id)
        .gte('recorded_at', mStart)
        .lte('recorded_at', mEnd)
      const bySpecies = {}
      ;(mData || []).forEach(c => {
        const s = c.species || 'Unknown'
        bySpecies[s] = (bySpecies[s] || 0) + (Number(c.weight) || 0)
      })
      trend.push({ month: d.toLocaleString('default', { month: 'short' }), species: bySpecies })
    }
    const allSpecies = new Set()
    trend.forEach(t => Object.keys(t.species).forEach(s => allSpecies.add(s)))
    const months = trend.map(t => t.month)
    const series = Array.from(allSpecies).map(species => ({
      species,
      data: trend.map(t => t.species[species] || 0)
    }))

    res.json({
      totalWeightToday,
      activeVessels,
      activitiesWeek: activitiesWeek || 0,
      topSpecies,
      trend: { months, series }
    })
  } catch (e) {
    res.status(500).json({ error: e.message })
  }
})

// --- ACTIVITY LOGS ---
app.get('/api/activity_logs/me', auth(), async (req, res) => {
  const { data, error } = await supabase.from('activity_logs').select('*').eq('user_id', req.user.id).order('created_at', { ascending: false })
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

app.post('/api/activity_logs', auth(), async (req, res) => {
  const { type, category, lat, lng, line, details } = req.body
  const { data, error } = await supabase.from('activity_logs').insert({
    user_id: req.user.id,
    type,
    category,
    location: { lat: parseFloat(lat), lng: parseFloat(lng) },
    geom_line: line || null,
    details: details ? { note: details } : null
  }).select().single()

  if (error) return res.status(400).json({ error: error.message })
  broadcast({ type: 'activity', item: data })
  res.json(data)
})

app.post('/api/activity_logs/upload', auth(), upload.single('photo'), async (req, res) => {
  try {
    const { type, category, lat, lng, line, note } = req.body
    let photoUrl = null

    if (req.file) {
      const fileContent = fs.readFileSync(req.file.path)
      const fileName = `activities/${req.user.id}/${Date.now()}_${req.file.originalname}`
      const { data, error } = await supabase.storage.from('uploads').upload(fileName, fileContent, {
        contentType: req.file.mimetype
      })
      if (error) throw error
      const { data: { publicUrl } } = supabase.storage.from('uploads').getPublicUrl(fileName)
      photoUrl = publicUrl
      fs.unlinkSync(req.file.path)
    }

    const { data, error } = await supabase.from('activity_logs').insert({
      user_id: req.user.id,
      type,
      category,
      location: { lat: parseFloat(lat), lng: parseFloat(lng) },
      geom_line: line ? JSON.parse(line) : null,
      image_url: photoUrl,
      details: note ? { note } : null
    }).select().single()

    if (error) throw error
    broadcast({ type: 'activity', item: data })
    res.json(data)
  } catch (e) {
    res.status(500).json({ error: e.message })
  }
})

// --- DATA ENDPOINTS ---

app.post('/api/status', auth(), async (req, res) => {
  const status = req.body.status
  const lat = req.body.lat
  const lng = req.body.lng
  const at = req.body.at || new Date().toISOString()
  
  const { data, error } = await supabase.from('status_events').insert({
    user_id: req.user.id,
    status,
    lat: Number(lat) || null,
    lng: Number(lng) || null,
    at
  }).select().single()

  if (error) return res.status(400).json({ error: error.message })

  // Update in-memory shim
  statusStateByUserId.set(req.user.id, { status, at, lat, lng })
  
  // If Port, stop tracking
  if (status === 'port') {
    const prev = trackingStateByUserId.get(req.user.id) || {}
    trackingStateByUserId.set(req.user.id, { ...prev, active: false })
    // Broadcast stop
    broadcast({ type: 'track_stop', userId: req.user.id, at, lat, lng })
  }

  broadcast({ type: 'status', ...data, userId: req.user.id })
  res.json({ ok: true, item: data })
})

app.post('/api/track', auth(), async (req, res) => {
  const { lat, lng, accuracy, speed, heading, recordedAt } = req.body
  const point = {
    user_id: req.user.id,
    lat, lng, accuracy, speed, heading,
    recorded_at: recordedAt || new Date().toISOString()
  }
  
  const { error } = await supabase.from('tracks').insert(point)
  if (error) return res.status(400).json({ error: error.message })

  // Shim state
  trackingStateByUserId.set(req.user.id, { active: true, lastPoint: point, lastSeenAt: Date.now() })
  
  // Get status
  const st = statusStateByUserId.get(req.user.id) || {}
  
  broadcast({ 
    type: 'track', 
    id: nanoid(), // Temp ID for frontend
    userId: req.user.id, 
    lat, lng, accuracy, speed, heading, recordedAt,
    active: true,
    status: st.status,
    statusAt: st.at
  })
  
  res.json({ ok: true })
})

app.post('/api/track/stop', auth(), async (req, res) => {
  const prev = trackingStateByUserId.get(req.user.id) || {}
  trackingStateByUserId.set(req.user.id, { ...prev, active: false })
  broadcast({ type: 'track_stop', userId: req.user.id, at: new Date().toISOString() })
  res.json({ ok: true })
})

app.post('/api/catches', auth(), async (req, res) => {
  const { species, netType, weightKg, lengthCm, gear, photoUrl, note, lat, lng, capturedAt } = req.body
  if (lat == null || lng == null) return res.status(400).json({ error: 'Missing coordinates' })

  let vesselInfo
  try {
    vesselInfo = await resolveCatchVesselSupabase(req.body)
  } catch (e) {
    return res.status(e.statusCode || 400).json({ error: e.message })
  }
  
  const { data, error } = await supabase.from('catches').insert({
    user_id: req.user.id,
    species: species || 'unknown',
    net_type: netType || null,
    weight: weightKg || null,
    length: lengthCm || null,
    gear: gear || null,
    vessel_id: vesselInfo.vessel_id,
    vessel: vesselInfo.vessel,
    vessel_registration_number: vesselInfo.vessel_registration_number,
    vessel_name: vesselInfo.vessel_name,
    owner_name: vesselInfo.owner_name,
    image_url: photoUrl || null,
    notes: note || null,
    lat, lng,
    recorded_at: capturedAt || new Date().toISOString()
  }).select().single()

  if (error) return res.status(400).json({ error: error.message })
  
  broadcast({ type: 'catch', item: { ...data, userId: req.user.id } })
  res.json(data)
})

// Catches & Upload
const upload = multer({ dest: 'uploads/' }) // Temp dir
app.post('/api/catches/upload', auth(), upload.single('photo'), async (req, res) => {
  try {
    const { species, netType, weightKg, lengthCm, gear, note, lat, lng, capturedAt } = req.body
    let photoUrl = null

    if (req.file) {
      const fileContent = fs.readFileSync(req.file.path)
      const fileName = `${req.user.id}/${Date.now()}_${req.file.originalname}`
      const { data, error } = await supabase.storage.from('uploads').upload(fileName, fileContent, {
        contentType: req.file.mimetype
      })
      if (error) throw error
      // Get public URL
      const { data: { publicUrl } } = supabase.storage.from('uploads').getPublicUrl(fileName)
      photoUrl = publicUrl
      fs.unlinkSync(req.file.path) // Cleanup
    }

    const vesselInfo = await resolveCatchVesselSupabase(req.body)
    const { data, error } = await supabase.from('catches').insert({
      user_id: req.user.id,
      species,
      weight: weightKg,
      length: lengthCm,
      net_type: netType,
      gear: gear,
      vessel_id: vesselInfo.vessel_id,
      vessel: vesselInfo.vessel,
      vessel_registration_number: vesselInfo.vessel_registration_number,
      vessel_name: vesselInfo.vessel_name,
      owner_name: vesselInfo.owner_name,
      image_url: photoUrl,
      notes: note,
      lat, lng,
      recorded_at: capturedAt || new Date().toISOString()
    }).select().single()

    if (error) throw error

    broadcast({ type: 'catch', item: { ...data, userId: req.user.id } })
    res.json(data)
  } catch (e) {
    console.error(e)
    res.status(500).json({ error: 'Upload failed: ' + e.message })
  }
})

app.get('/api/catches/me', auth(), async (req, res) => {
  const { data, error } = await supabase.from('catches').select('*, vessels(*)').eq('user_id', req.user.id)
  if (error) return res.status(400).json({ error: error.message })
  res.json((data || []).map(c => ({
    ...c,
    userId: c.user_id,
    vesselId: c.vessel_id,
    vesselRegistrationNumber: c.vessel_registration_number,
    vesselName: c.vessel_name,
    ownerName: c.owner_name,
    barangay: c.vessels ? c.vessels.barangay : null,
    weightKg: c.weight,
    lengthCm: c.length,
    netType: c.net_type,
    capturedAt: c.recorded_at,
    photoUrl: c.image_url,
    note: c.notes
  })))
})

app.get('/api/catches', auth('admin'), async (req, res) => {
  const { userId, vesselId, from, to } = req.query
  let query = supabase.from('catches').select('*, profiles(id, name, email), vessels(*)')
  if (userId) query = query.eq('user_id', userId)
  if (vesselId && vesselId !== '__unassigned__') {
    const vid = String(vesselId)
    query = query.or(`vessel_id.eq.${vid},vessel_registration_number.ilike.${vid},vessel_name.ilike.${vid}`)
  } else if (vesselId === '__unassigned__') {
    query = query.is('vessel_id', null).is('vessel_registration_number', null).is('vessel_name', null)
  }
  if (from) query = query.gte('recorded_at', new Date(from).toISOString())
  if (to) query = query.lte('recorded_at', new Date(to).toISOString())
  query = query.order('recorded_at', { ascending: false })
  const { data: catches, error: cErr } = await query
  if (cErr) return res.status(400).json({ error: cErr.message })
  
  const list = (catches || []).map(c => ({
    ...c,
    user: c.profiles ? { id: c.profiles.id, name: c.profiles.name, email: c.profiles.email } : null,
    userId: c.user_id,
    vesselId: c.vessel_id,
    vesselRegistrationNumber: c.vessel_registration_number,
    vesselName: c.vessel_name,
    ownerName: c.owner_name,
    barangay: c.vessels ? c.vessels.barangay : null,
    weightKg: c.weight,
    lengthCm: c.length,
    netType: c.net_type,
    capturedAt: c.recorded_at,
    photoUrl: c.image_url,
    note: c.notes
  }))
  res.json(list)
})

app.patch('/api/admin/catches/:id', auth('admin'), async (req, res) => {
  const id = req.params.id
  const { species, weightKg, lengthCm, gear, note } = req.body
  
  const updates = {}
  if (species !== undefined) updates.species = species
  if (weightKg !== undefined) updates.weight = weightKg
  if (lengthCm !== undefined) updates.length = lengthCm
  if (gear !== undefined) updates.gear = gear
  if (note !== undefined) updates.notes = note
  if (req.body.vesselId !== undefined) {
    try {
      const vesselInfo = await resolveCatchVesselSupabase(req.body)
      updates.vessel_id = vesselInfo.vessel_id
      updates.vessel = vesselInfo.vessel
      updates.vessel_registration_number = vesselInfo.vessel_registration_number
      updates.vessel_name = vesselInfo.vessel_name
      updates.owner_name = vesselInfo.owner_name
    } catch (e) {
      return res.status(e.statusCode || 400).json({ error: e.message })
    }
  }

  const { error } = await supabase.from('catches').update(updates).eq('id', id)
  if (error) return res.status(400).json({ error: error.message })
  res.json({ ok: true })
})

app.delete('/api/admin/catches/:id', auth('admin'), async (req, res) => {
  const id = req.params.id
  const { error } = await supabase.from('catches').delete().eq('id', id)
  if (error) return res.status(400).json({ error: error.message })
  res.json({ ok: true })
})

app.get('/api/admin/catches/summary', auth('admin'), async (req, res) => {
  const { data: catches, error: cErr } = await supabase.from('catches').select('*, vessels(*)').order('recorded_at', { ascending: false })
  if (cErr) return res.status(400).json({ error: cErr.message })
  const byVessel = new Map()
  ;(catches || []).forEach(c => {
    const v = c.vessels || {}
    const info = {
      vesselId: c.vessel_id || null,
      ownerName: v.owner_name || c.owner_name || null,
      barangay: v.barangay || c.barangay || null,
      registrationNumber: v.vessel_registration_number || c.vessel_registration_number || null,
      vesselName: v.vessel_name || c.vessel_name || null
    }
    let key
    if (info.vesselId) key = 'id:' + info.vesselId
    else if (info.registrationNumber) key = 'reg:' + info.registrationNumber
    else if (info.vesselName) key = 'name:' + info.vesselName
    else key = '__unassigned__'
    const t = new Date(c.recorded_at || c.created_at || 0).getTime()
    const cur = byVessel.get(key)
    if (!cur) {
      byVessel.set(key, {
        vesselId: info.vesselId,
        ownerName: info.ownerName,
        barangay: info.barangay,
        registrationNumber: info.registrationNumber,
        vesselName: info.vesselName,
        latestSpecies: c.species || null,
        latestCapturedAt: c.recorded_at || c.created_at,
        _t: t,
        totalCatches: 1,
        latestUserId: c.user_id || null
      })
    } else {
      cur.totalCatches += 1
      if (t > cur._t) {
        cur._t = t
        cur.latestSpecies = c.species || null
        cur.latestCapturedAt = c.recorded_at || c.created_at
        cur.latestUserId = c.user_id || null
      }
      if (!cur.ownerName && info.ownerName) cur.ownerName = info.ownerName
      if (!cur.barangay && info.barangay) cur.barangay = info.barangay
      if (!cur.registrationNumber && info.registrationNumber) cur.registrationNumber = info.registrationNumber
      if (!cur.vesselName && info.vesselName) cur.vesselName = info.vesselName
      if (!cur.vesselId && info.vesselId) cur.vesselId = info.vesselId
    }
  })
  const out = Array.from(byVessel.values()).map(x => {
    const { _t, ...rest } = x; return rest
  }).sort((a, b) => {
    const aT = a.latestCapturedAt ? new Date(a.latestCapturedAt).getTime() : 0
    const bT = b.latestCapturedAt ? new Date(b.latestCapturedAt).getTime() : 0
    return bT - aT
  })
  res.json(out)
})

app.delete('/api/admin/catches/user/:userId', auth('admin'), async (req, res) => {
  const userId = String(req.params.userId)
  const { data: exists, error: e1 } = await supabase.from('catches').select('id').eq('user_id', userId)
  if (e1) return res.status(400).json({ error: e1.message })
  if (!exists || exists.length === 0) return res.status(404).json({ error: 'No catches found for this user' })
  const { error } = await supabase.from('catches').delete().eq('user_id', userId)
  if (error) return res.status(400).json({ error: error.message })
  res.json({ ok: true, deleted: exists.length })
})

app.delete('/api/admin/catches/vessel/:vesselId', auth('admin'), async (req, res) => {
  const vesselId = String(req.params.vesselId)
  let existsQuery
  if (vesselId === '__unassigned__') {
    existsQuery = supabase.from('catches').select('id').is('vessel_id', null).is('vessel_registration_number', null).is('vessel_name', null)
  } else {
    existsQuery = supabase.from('catches').select('id').or(`vessel_id.eq.${vesselId},vessel_registration_number.ilike.${vesselId},vessel_name.ilike.${vesselId}`)
  }
  const { data: exists, error: e1 } = await existsQuery
  if (e1) return res.status(400).json({ error: e1.message })
  if (!exists || exists.length === 0) return res.status(404).json({ error: 'No catches found for this vessel' })
  let delQuery
  if (vesselId === '__unassigned__') {
    delQuery = supabase.from('catches').delete().is('vessel_id', null).is('vessel_registration_number', null).is('vessel_name', null)
  } else {
    delQuery = supabase.from('catches').delete().or(`vessel_id.eq.${vesselId},vessel_registration_number.ilike.${vesselId},vessel_name.ilike.${vesselId}`)
  }
  const { error } = await delQuery
  if (error) return res.status(400).json({ error: error.message })
  res.json({ ok: true, deleted: exists.length })
})

app.patch('/api/catches/:id', auth(), async (req, res) => {
  const id = req.params.id
  const { species, weightKg, lengthCm, gear, note } = req.body
  const { data: existing, error: ePre } = await supabase.from('catches').select('user_id').eq('id', id).maybeSingle()
  if (ePre || !existing) return res.status(404).json({ error: 'Not found' })
  if (!isSelfOrAdmin(req, existing.user_id)) return res.status(403).json({ error: 'Forbidden' })
  const updates = {}
  if (species !== undefined) updates.species = species
  if (weightKg !== undefined) updates.weight = weightKg
  if (lengthCm !== undefined) updates.length = lengthCm
  if (gear !== undefined) updates.gear = gear
  if (note !== undefined) updates.notes = note
  if (req.body.vesselId !== undefined) {
    try {
      const vesselInfo = await resolveCatchVesselSupabase(req.body)
      updates.vessel_id = vesselInfo.vessel_id
      updates.vessel = vesselInfo.vessel
      updates.vessel_registration_number = vesselInfo.vessel_registration_number
      updates.vessel_name = vesselInfo.vessel_name
      updates.owner_name = vesselInfo.owner_name
    } catch (e) {
      return res.status(e.statusCode || 400).json({ error: e.message })
    }
  }
  const { error } = await supabase.from('catches').update(updates).eq('id', id)
  if (error) return res.status(400).json({ error: error.message })
  res.json({ ok: true })
})

app.delete('/api/catches/:id', auth(), async (req, res) => {
  const id = req.params.id
  const { data: existing, error: ePre } = await supabase.from('catches').select('user_id').eq('id', id).maybeSingle()
  if (ePre || !existing) return res.status(404).json({ error: 'Not found' })
  if (!isSelfOrAdmin(req, existing.user_id)) return res.status(403).json({ error: 'Forbidden' })
  const { error } = await supabase.from('catches').delete().eq('id', id)
  if (error) return res.status(400).json({ error: error.message })
  res.json({ ok: true })
})

app.get('/api/live_locations', auth(), async (req, res) => {
  const currentUserId = String(req.user.id)
  const active = []
  trackingStateByUserId.forEach((v, k) => {
    if (v.active && String(k) === currentUserId) {
      active.push({ userId: k, ...v.lastPoint, active: true, lastSeenAt: v.lastSeenAt })
    }
  })
  res.json(active)
})

app.get('/api/admin/live_locations', auth('admin'), async (req, res) => {
  // Get user profiles and vessels from supabase
  const { data: profiles } = await supabase.from('profiles').select('*')
  const { data: vessels } = await supabase.from('vessels').select('*')
  
  // Get latest track points from database for all users
  const { data: tracks } = await supabase
    .from('tracks')
    .select('*, user_id, recorded_at')
    .order('recorded_at', { ascending: false })
  
  // Get latest status events from database
  const { data: statusEvents } = await supabase
    .from('status_events')
    .select('*, user_id, at')
    .order('at', { ascending: false })
  
  const latestByUserId = new Map()
  
  // Process status events first
  statusEvents.forEach(st => {
    const userId = st.user_id ? String(st.user_id) : null
    if (!userId) return
    const lat = st.lat != null ? Number(st.lat) : NaN
    const lng = st.lng != null ? Number(st.lng) : NaN
    if (!Number.isFinite(lat) || !Number.isFinite(lng)) return
    const at = st.at ? String(st.at) : null
    const t = at ? new Date(at).getTime() : NaN
    if (!Number.isFinite(t)) return
    latestByUserId.set(userId, { 
      userId, 
      lat, 
      lng, 
      accuracy: null, 
      speed: null, 
      heading: null, 
      recordedAt: at, 
      status: st.status,
      statusAt: at,
      _t: t 
    })
  })
  
  // Process track points, overriding if newer
  tracks.forEach(p => {
    const userId = p.user_id ? String(p.user_id) : null
    if (!userId) return
    const recordedAt = p.recorded_at ? String(p.recorded_at) : null
    const t = recordedAt ? new Date(recordedAt).getTime() : NaN
    if (!Number.isFinite(t)) return
    const cur = latestByUserId.get(userId)
    if (!cur || t > cur._t) {
      latestByUserId.set(userId, { 
        userId,
        id: p.id,
        lat: Number(p.lat),
        lng: Number(p.lng),
        accuracy: p.accuracy,
        speed: p.speed,
        heading: p.heading,
        recordedAt,
        status: cur ? cur.status : null,
        statusAt: cur ? cur.statusAt : null,
        _t: t 
      })
    }
  })
  
  // Merge with in-memory tracking state
  trackingStateByUserId.forEach((v, k) => {
    const userId = String(k)
    const cur = latestByUserId.get(userId)
    if (!cur || (v.lastSeenAt && new Date(v.lastSeenAt).getTime() > (cur._t || 0))) {
      latestByUserId.set(userId, {
        userId,
        ...v.lastPoint,
        active: v.active,
        lastSeenAt: v.lastSeenAt,
        status: statusStateByUserId.get(userId) ? statusStateByUserId.get(userId).status : (cur ? cur.status : null),
        statusAt: statusStateByUserId.get(userId) ? statusStateByUserId.get(userId).at : (cur ? cur.statusAt : null),
        _t: v.lastSeenAt ? new Date(v.lastSeenAt).getTime() : (cur ? cur._t : Date.now())
      })
    } else if (cur) {
      cur.active = v.active
      cur.lastSeenAt = v.lastSeenAt
    }
  })
  
  const out = Array.from(latestByUserId.values())
    .sort((a, b) => b._t - a._t)
    .map(p => {
      const u = profiles ? profiles.find(x => String(x.id) === String(p.userId)) : null
      const { _t, ...rest } = p
      
      // Determine active status
      let active = rest.active !== false
      if (rest.status === 'port') active = false
      
      // Find vessel info for this user
      let vesselInfo = null
      if (vessels) {
        if (rest.vesselId) {
          vesselInfo = vessels.find(v => String(v.id) === String(rest.vesselId))
        }
        if (!vesselInfo && rest.vesselRegistrationNumber) {
          vesselInfo = vessels.find(v => v.vessel_registration_number === rest.vesselRegistrationNumber)
        }
        if (!vesselInfo && u) {
          // Try to find by owner name
          vesselInfo = vessels.find(v => v.owner_name && v.owner_name.toLowerCase().includes((u.name || '').toLowerCase()))
        }
      }
      
      return { 
        ...rest, 
        active,
        user: u ? { ...u } : null, // include all user fields
        vesselId: vesselInfo ? vesselInfo.id : rest.vesselId,
        vesselRegistrationNumber: vesselInfo ? vesselInfo.vessel_registration_number : rest.vesselRegistrationNumber,
        vesselName: vesselInfo ? vesselInfo.vessel_name : rest.vesselName,
        ownerName: vesselInfo ? vesselInfo.owner_name : rest.ownerName,
        barangay: vesselInfo ? vesselInfo.barangay : rest.barangay
      }
    })

  res.json(out)
})

app.get('/api/users', auth('admin'), async (req, res) => {
  const { data, error } = await supabase.from('profiles').select('*').order('created_at', { ascending: false })
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

app.get('/api/admin/users', auth('admin'), async (req, res) => {
  const { data, error } = await supabase.from('profiles').select('*').order('created_at', { ascending: false })
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

app.get('/api/status_history', auth(), async (req, res) => {
  const { userId, limit } = req.query
  const selfId = String(req.user.id || '')
  let q = supabase.from('status_events').select('*').order('at', { ascending: false }).limit(Number(limit)||50)
  if (isAdmin(req.user)) {
    if (userId) q = q.eq('user_id', userId)
  } else {
    if (userId && String(userId) !== selfId) return res.status(403).json({ error: 'Forbidden' })
    q = q.eq('user_id', selfId)
  }
  const { data, error } = await q
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

app.get('/api/admin/status_history', auth('admin'), async (req, res) => {
  const { userId, limit } = req.query
  let q = supabase.from('status_events').select('*').order('at', { ascending: false }).limit(Number(limit)||50)
  if (userId) q = q.eq('user_id', userId)
  const { data, error } = await q
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

// --- TRACKS ENDPOINTS ---
app.get('/api/track/me', auth(), async (req, res) => {
  const { data, error } = await supabase
    .from('tracks')
    .select('*')
    .eq('user_id', req.user.id)
    .order('recorded_at', { ascending: false })
  if (error) return res.status(400).json({ error: error.message })
  res.json((data || []).map(t => ({
    id: t.id,
    userId: t.user_id,
    lat: t.lat,
    lng: t.lng,
    accuracy: t.accuracy,
    speed: t.speed,
    heading: t.heading,
    recordedAt: t.recorded_at
  })))
})

app.get('/api/admin/tracks', auth('admin'), async (req, res) => {
  const { data, error } = await supabase
    .from('tracks')
    .select('*, profiles(id, name, email)')
    .order('recorded_at', { ascending: false })
  if (error) return res.status(400).json({ error: error.message })
  const list = (data || []).map(t => ({
    id: t.id,
    userId: t.user_id,
    lat: t.lat,
    lng: t.lng,
    accuracy: t.accuracy,
    speed: t.speed,
    heading: t.heading,
    recordedAt: t.recorded_at,
    user: t.profiles ? { id: t.profiles.id, name: t.profiles.name, email: t.profiles.email } : null
  }))
  res.json(list)
})

app.delete('/api/admin/tracks/:id', auth('admin'), async (req, res) => {
  const id = req.params.id
  const { error } = await supabase.from('tracks').delete().eq('id', id)
  if (error) return res.status(400).json({ error: error.message })
  res.json({ ok: true })
})

// --- SPECIES ENDPOINTS ---
app.get('/api/species', async (req, res) => {
  const { data, error } = await supabase.from('species').select('name').order('name')
  if (error) return res.status(400).json({ error: error.message })
  res.json((data || []).map(s => s.name))
})

app.get('/api/admin/species', auth('admin'), async (req, res) => {
  const { data, error } = await supabase.from('species').select('name').order('name')
  if (error) return res.status(400).json({ error: error.message })
  res.json((data || []).map(s => s.name))
})

app.post('/api/admin/species', auth('admin'), async (req, res) => {
  const { name } = req.body
  if (!name) return res.status(400).json({ error: 'Name required' })
  const { data: existing } = await supabase.from('species').select('name').eq('name', name).maybeSingle()
  if (existing) return res.status(409).json({ error: 'Exists' })
  const { error } = await supabase.from('species').insert({ name })
  if (error) return res.status(400).json({ error: error.message })
  res.json({ ok: true })
})

app.delete('/api/admin/species', auth('admin'), async (req, res) => {
  const { name } = req.body
  const { error } = await supabase.from('species').delete().eq('name', name)
  if (error) return res.status(400).json({ error: error.message })
  res.json({ ok: true })
})

// --- ALERTS ENDPOINTS ---
app.get('/api/admin/alerts', auth(['admin','inspector']), async (req, res) => {
  let q = supabase
    .from('alerts')
    .select('*, profiles(id, name, email)')
    .order('recorded_at', { ascending: false })
  if (!isAdmin(req.user)) {
    q = q.eq('user_id', req.user.id)
  }
  const { data, error } = await q
  if (error) return res.status(400).json({ error: error.message })
  const mapped = (data || []).map(a => ({
    ...a,
    userId: a.user_id,
    userName: a.user_name,
    recordedAt: a.recorded_at,
    user: a.profiles ? { id: a.profiles.id, name: a.profiles.name, email: a.profiles.email } : null
  }))
  res.json(mapped)
})

app.patch('/api/admin/alerts/:id', auth(['admin','inspector']), async (req, res) => {
  const id = req.params.id
  const { status, note } = req.body
  const { data: existing, error: e1 } = await supabase.from('alerts').select('*').eq('id', id).maybeSingle()
  if (e1 || !existing) return res.status(404).json({ error: 'Not found' })
  if (!isSelfOrAdmin(req, existing.user_id)) return res.status(403).json({ error: 'Forbidden' })
  const next = { status: status || existing.status, note: note ?? existing.note }
  const { error } = await supabase.from('alerts').update(next).eq('id', id)
  if (error) return res.status(400).json({ error: error.message })
  res.json({ ok: true })
})

app.delete('/api/admin/alerts/:id', auth('admin'), async (req, res) => {
  const id = req.params.id
  const { data: existing, error: e1 } = await supabase.from('alerts').select('id').eq('id', id).maybeSingle()
  if (e1 || !existing) return res.status(404).json({ error: 'Not found' })
  const { error } = await supabase.from('alerts').delete().eq('id', id)
  if (error) return res.status(400).json({ error: error.message })
  res.json({ ok: true })
})

app.post('/api/alerts', auth(), async (req, res) => {
  const { type, lat, lng, note } = req.body
  if (!type || lat == null || lng == null) return res.status(400).json({ error: 'Missing fields' })
  const { data: profile } = await supabase.from('profiles').select('name').eq('id', req.user.id).maybeSingle()
  const { data, error } = await supabase.from('alerts').insert({
    type: String(type),
    status: 'pending',
    note: note || null,
    user_id: req.user.id,
    user_name: profile ? profile.name : null,
    lat: parseFloat(lat),
    lng: parseFloat(lng),
    recorded_at: new Date().toISOString()
  }).select().single()
  if (error) return res.status(400).json({ error: error.message })
  broadcast({ type: 'alert', item: { ...data, userId: data.user_id, userName: data.user_name, recordedAt: data.recorded_at } })
  res.json(data)
})

app.post('/api/alerts/create', auth(), async (req, res) => {
  const { type, lat, lng, note } = req.body
  if (!type || lat == null || lng == null) return res.status(400).json({ error: 'Missing fields' })
  const { data: profile } = await supabase.from('profiles').select('name').eq('id', req.user.id).maybeSingle()
  const { data, error } = await supabase.from('alerts').insert({
    type: String(type),
    status: 'pending',
    note: note || null,
    user_id: req.user.id,
    user_name: profile ? profile.name : null,
    lat: parseFloat(lat),
    lng: parseFloat(lng),
    recorded_at: new Date().toISOString()
  }).select().single()
  if (error) return res.status(400).json({ error: error.message })
  broadcast({ type: 'alert', item: { ...data, userId: data.user_id, userName: data.user_name, recordedAt: data.recorded_at } })
  res.json(data)
})

app.get('/api/test_alerts', (req, res) => { res.json({ ok: true }) })

// --- PROTECTED AREAS ENDPOINTS ---
app.get('/api/admin/protected_areas', auth('admin'), async (req, res) => {
  const { data, error } = await supabase
    .from('protected_areas')
    .select('*')
    .order('created_at', { ascending: false })
  if (error) return res.status(400).json({ error: error.message })
  res.json((data || []).map(pa => ({
    id: pa.id,
    name: pa.name,
    geom: pa.geom || pa.geometry,
    rules: pa.rules,
    createdAt: pa.created_at,
    updatedAt: pa.updated_at
  })))
})

app.post('/api/admin/protected_areas', auth('admin'), async (req, res) => {
  const { name, geom, rules } = req.body
  if (!geom) return res.status(400).json({ error: 'Geom required' })
  const { data, error } = await supabase
    .from('protected_areas')
    .insert({ name: name || 'Unnamed Zone', geom, rules: rules || null })
    .select('*')
    .single()
  if (error) return res.status(400).json({ error: error.message })
  res.json({
    id: data.id,
    name: data.name,
    geom: data.geom,
    rules: data.rules,
    createdAt: data.created_at
  })
})

app.patch('/api/admin/protected_areas/:id', auth('admin'), async (req, res) => {
  const id = req.params.id
  const { name, geom, rules } = req.body
  const { data: existing, error: e1 } = await supabase.from('protected_areas').select('*').eq('id', id).maybeSingle()
  if (e1 || !existing) return res.status(404).json({ error: 'Not found' })
  const next = {}
  if (name !== undefined) next.name = name
  if (geom !== undefined) next.geom = geom
  if (rules !== undefined) next.rules = rules
  next.updated_at = new Date().toISOString()
  const { error } = await supabase.from('protected_areas').update(next).eq('id', id)
  if (error) return res.status(400).json({ error: error.message })
  res.json({ ok: true })
})

app.delete('/api/admin/protected_areas/:id', auth('admin'), async (req, res) => {
  const id = req.params.id
  const { data: existing, error: e1 } = await supabase.from('protected_areas').select('id').eq('id', id).maybeSingle()
  if (e1 || !existing) return res.status(404).json({ error: 'Not found' })
  const { error } = await supabase.from('protected_areas').delete().eq('id', id)
  if (error) return res.status(400).json({ error: error.message })
  res.json({ ok: true })
})

// --- ACTIVITY LOGS ENDPOINTS ---
app.get('/api/activity_logs', auth(['admin','inspector']), async (req, res) => {
  const { type, userId, from, to, format } = req.query
  const selfId = String(req.user.id || '')
  let q = supabase.from('activity_logs').select('*, profiles(id, name, email)').order('created_at', { ascending: false }).limit(500)
  if (isAdmin(req.user)) {
    if (userId) q = q.eq('user_id', userId)
  } else {
    if (userId && String(userId) !== selfId) return res.status(403).json({ error: 'Forbidden' })
    q = q.eq('user_id', selfId)
  }
  if (type) q = q.eq('type', type)
  if (from) q = q.gte('created_at', from)
  if (to) q = q.lte('created_at', to + 'T23:59:59')
  const { data, error } = await q
  if (error) return res.status(400).json({ error: error.message })
  const out = (data || []).map(a => ({
    id: a.id,
    user_id: a.user_id,
    userId: a.user_id,
    type: a.type,
    category: a.category,
    location: a.location,
    geom_line: a.geom_line,
    details: a.details,
    image_url: a.image_url,
    photoUrl: a.image_url,
    created_at: a.created_at,
    user: a.profiles ? { id: a.profiles.id, name: a.profiles.name, email: a.profiles.email } : null
  }))
  if (format === 'geojson') {
    const features = []
    out.forEach(a => {
      if (a.location && a.location.lng != null) features.push({ type: 'Feature', geometry: { type: 'Point', coordinates: [a.location.lng, a.location.lat] }, properties: { id: a.id, type: a.type, category: a.category || null, user_id: a.user_id, created_at: a.created_at } })
      if (Array.isArray(a.geom_line)) features.push({ type: 'Feature', geometry: { type: 'LineString', coordinates: a.geom_line.map(p => [p.lng, p.lat]) }, properties: { id: a.id, type: a.type, category: a.category || null, user_id: a.user_id, created_at: a.created_at } })
    })
    return res.json({ type: 'FeatureCollection', features })
  }
  res.json(out)
})

app.delete('/api/activity_logs/:id', auth(['admin','inspector']), async (req, res) => {
  const id = req.params.id
  const { data: existing, error: ePre } = await supabase.from('activity_logs').select('user_id').eq('id', id).maybeSingle()
  if (ePre || !existing) return res.status(404).json({ error: 'Not found' })
  if (!isSelfOrAdmin(req, existing.user_id)) return res.status(403).json({ error: 'Forbidden' })
  const { error } = await supabase.from('activity_logs').delete().eq('id', id)
  if (error) return res.status(400).json({ error: error.message })
  res.json({ ok: true })
})

app.get('/api/admin/activity_insights', auth('admin'), async (req, res) => {
  const startOfWeek = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString()
  const { count, error } = await supabase
    .from('activity_logs')
    .select('*', { count: 'exact', head: true })
    .gte('created_at', startOfWeek)
  if (error) return res.status(400).json({ error: error.message })
  res.json({
    illegal_in_protected: 0,
    approaches_last7: count || 0,
    patrol_km: 0
  })
})

// --- IMAGES ENDPOINTS ---
app.post('/api/images', auth(), async (req, res) => {
  const { catch_id, bucket_key, exif } = req.body
  if (!catch_id || !bucket_key) return res.status(400).json({ error: 'Missing fields' })
  const { data, error } = await supabase
    .from('images')
    .insert({
      catch_id,
      bucket_key,
      exif: exif || null,
      created_at: new Date().toISOString()
    })
    .select()
    .single()
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

app.get('/api/images', auth(), async (req, res) => {
  const { data, error } = await supabase.from('images').select('*').order('created_at', { ascending: false })
  if (error) return res.status(400).json({ error: error.message })
  res.json(data || [])
})

const tileCache = new Map()
const BLANK_PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+lmZkAAAAASUVORK5CYII=', 'base64')
const https = require('https')
app.get('/api/public/tiles/:z/:x/:y.png', async (req, res) => {
  try {
    const z = String(req.params.z || '')
    const x = String(req.params.x || '')
    const y = String(req.params.y || '')
    if (!/^\d+$/.test(z) || !/^\d+$/.test(x) || !/^\d+$/.test(y)) {
      res.setHeader('Content-Type', 'image/png')
      res.setHeader('Cache-Control', 'public, max-age=3600')
      return res.send(BLANK_PNG)
    }

    const key = `${z}/${x}/${y}`
    const now = Date.now()
    const cached = tileCache.get(key)
    if (cached && cached.expiresAt > now) {
      res.setHeader('Content-Type', cached.contentType)
      res.setHeader('Cache-Control', 'public, max-age=86400')
      return res.send(cached.body)
    }

    const upstream = `https://tile.openstreetmap.org/${key}.png`
    let status = 502
    let contentType = 'image/png'
    let body = null
    if (typeof fetch === 'function') {
      const r = await fetch(upstream, { redirect: 'follow', headers: { 'User-Agent': 'capstone-pro' } })
      status = r.status
      if (r.ok) {
        contentType = r.headers.get('content-type') || 'image/png'
        body = Buffer.from(await r.arrayBuffer())
      }
    } else {
      const result = await new Promise((resolve, reject) => {
        const upstreamReq = https.get(upstream, { headers: { 'User-Agent': 'capstone-pro' } }, (upstreamRes) => {
          const chunks = []
          upstreamRes.on('data', (c) => chunks.push(c))
          upstreamRes.on('end', () => resolve({
            status: upstreamRes.statusCode || 502,
            contentType: String(upstreamRes.headers['content-type'] || 'image/png'),
            body: Buffer.concat(chunks)
          }))
        })
        upstreamReq.on('error', reject)
      })
      status = result.status
      contentType = result.contentType
      body = result.body
      if (status < 200 || status >= 300) body = null
    }

    if (!body) {
      res.setHeader('Content-Type', 'image/png')
      res.setHeader('Cache-Control', 'public, max-age=300')
      return res.send(BLANK_PNG)
    }

    tileCache.set(key, { body, contentType, expiresAt: now + 24 * 60 * 60 * 1000 })
    if (tileCache.size > 600) {
      for (const k of tileCache.keys()) { tileCache.delete(k); if (tileCache.size <= 500) break }
    }

    res.setHeader('Content-Type', contentType)
    res.setHeader('Cache-Control', 'public, max-age=86400')
    res.send(body)
  } catch {
    res.setHeader('Content-Type', 'image/png')
    res.setHeader('Cache-Control', 'public, max-age=60')
    res.send(BLANK_PNG)
  }
})

app.get('/api/public/config', (req, res) => {
  res.json({ mapboxToken: MAPBOX_TOKEN, vapidPublicKey: VAPID_PUBLIC })
})

// SSE Endpoint — heartbeat every 30s so intermediate TCP proxies don't drop idle connection
app.get('/api/admin/live', auth(['admin','inspector']), (req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Connection': 'keep-alive' })
  res.write('\n')
  sseClients.push(res)

  const hb = setInterval(() => {
    if (!res.destroyed) {
      try { res.write(':\n\n') } catch (_) {}
    }
  }, 30000)

  const cleanup = () => {
    clearInterval(hb)
    const idx = sseClients.indexOf(res)
    if (idx !== -1) sseClients.splice(idx, 1)
  }
  req.on('close', cleanup)
  req.on('error', cleanup)
})

/* ---------- Vercel AI SDK routes (AI Gateway activates on Vercel deploy) ---------- */
let _ai = null
let _openai = null
let _anthropic = null
try { _ai = require('ai') } catch (e) { console.warn('[ai] ai package not installed:', e && e.message) }
try { _openai = require('@ai-sdk/openai') } catch (e) { console.warn('[ai] @ai-sdk/openai not installed:', e && e.message) }
try { _anthropic = require('@ai-sdk/anthropic') } catch (e) { console.warn('[ai] @ai-sdk/anthropic not installed:', e && e.message) }

function _pickAiModel() {
  if (!_ai) return null
  if (process.env.OPENAI_API_KEY && _openai && typeof _openai.openai === 'function') {
    try { return _openai.openai(process.env.OPENAI_MODEL || 'gpt-4o-mini') } catch (e) { console.warn('[ai] openai() factory failed:', e && e.message) }
  }
  if (process.env.ANTHROPIC_API_KEY && _anthropic && typeof _anthropic.anthropic === 'function') {
    try { return _anthropic.anthropic(process.env.ANTHROPIC_MODEL || 'claude-3-5-sonnet-20240620') } catch (e) { console.warn('[ai] anthropic() factory failed:', e && e.message) }
  }
  return null
}

const BFAR_AI_SYSTEM_CHAT = `You are a helpful BFAR (Bureau of Fisheries and Aquatic Resources, Philippines) field assistant. 
Answer questions about: vessel registration, catch size limits, protected/endangered species, 
BFAR reporting deadlines, zoning for municipal vs commercial waters, and Philippine fisheries law.
Keep answers concise (under 250 words when possible). If you reference law, cite specific Republic Acts 
(e.g. RA 8550 Philippine Fisheries Code of 1998, RA 10654 amendments, RA 9147 Wildlife Act) when relevant. 
Do NOT fabricate specific section numbers if you are not confident — say "please cross-check with the latest BFAR AO (Administrative Order)" instead.`

const BFAR_AI_SYSTEM_CATCH_ANALYSIS = `You are a BFAR fisheries compliance and stock-health analyst (Philippines).
Return ONLY a valid JSON object with keys:
  "summary":      one-paragraph plain text (< 160 chars),
  "bfarNotes":    one-paragraph regulatory notes mentioning RA 8550 / RA 10654 / Wildlife Act / BFAR AO if applicable,
  "stockHealth":  one of: "LOW" | "MEDIUM" | "HIGH" | "UNKNOWN",
  "recommendedActions": array of 0-4 short string actions an inspector could take next (<= 80 chars each).
No markdown fences, no extra commentary. Strict JSON only.`

app.post('/api/ai/chat', auth(), async (req, res) => {
  const model = _pickAiModel()
  if (!model || !_ai) return res.status(503).json({ error: 'AI not configured. Add OPENAI_API_KEY or ANTHROPIC_API_KEY to environment.' })
  const { messages = [] } = req.body || {}
  try {
    const { streamText } = _ai
    const result = streamText({
      model,
      system: BFAR_AI_SYSTEM_CHAT,
      messages: Array.isArray(messages) ? messages : [],
      temperature: 0.2,
      maxSteps: 1,
      onFinish: ({ usage, finishReason }) => {
        try { console.log(`[ai/chat] user=${req.user && req.user.id} finish=${finishReason} usage=${JSON.stringify(usage)}`) } catch {}
      },
    })
    res.setHeader('Content-Type', 'text/plain; charset=utf-8')
    res.setHeader('Transfer-Encoding', 'chunked')
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate')
    res.flushHeaders && res.flushHeaders()
    for await (const chunk of result.textStream) {
      if (chunk) res.write(chunk)
    }
    res.end()
  } catch (err) {
    try { console.error('[ai/chat] error', err && err.stack || err) } catch {}
    if (res.headersSent) { try { res.end() } catch {} }
    else res.status(500).json({ error: (err && err.message) || String(err) })
  }
})

app.post('/api/ai/catch-analysis', auth(), async (req, res) => {
  const model = _pickAiModel()
  if (!model || !_ai) return res.status(503).json({ error: 'AI not configured. Add OPENAI_API_KEY or ANTHROPIC_API_KEY to environment.' })
  const { species = '', weightKg = null, location = '', notes = '', capturedAt = '' } = req.body || {}
  try {
    const { generateText } = _ai
    const promptLines = [
      'Inspect this catch report from a BFAR field inspector and return the strict JSON shape requested in system.',
      `species: ${species || '(not provided)'}`,
      `weightKg: ${weightKg === null || weightKg === '' ? '(not provided)' : String(weightKg)}`,
      `capturedAt: ${capturedAt || '(not provided)'}`,
      `location: ${location || '(not provided)'}`,
      `inspector notes: ${notes || '(none)'}`,
      `reporter userId: ${req.user && req.user.id} (${req.user && req.user.role})`,
    ]
    const { text, usage, finishReason } = await generateText({
      model,
      system: BFAR_AI_SYSTEM_CATCH_ANALYSIS,
      prompt: promptLines.join('\n'),
      temperature: 0.2,
      maxRetries: 1,
    })
    let analysis
    try {
      const cleaned = String(text || '').replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/i, '').trim()
      analysis = JSON.parse(cleaned)
    } catch {
      analysis = {
        summary: (text || '').slice(0, 160),
        bfarNotes: '',
        stockHealth: 'UNKNOWN',
        recommendedActions: [],
        _rawText: text,
      }
    }
    try { console.log(`[ai/catch-analysis] user=${req.user && req.user.id} finish=${finishReason} usage=${JSON.stringify(usage)}`) } catch {}
    res.json({ ok: true, usage: usage || null, analysis })
  } catch (err) {
    try { console.error('[ai/catch-analysis] error', err && err.stack || err) } catch {}
    res.status(500).json({ error: (err && err.message) || String(err) })
  }
})

if (IS_SERVERLESS) {
  module.exports = app
} else if (require.main === module) {
  const PORT = process.env.PORT || 3001
  app.listen(PORT, () => {
    console.log(`Supabase Server running on port ${PORT}`)
  })
} else {
  module.exports = app
}

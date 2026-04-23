require('dotenv').config()
const express = require('express')
const cors = require('cors')
const { createClient } = require('@supabase/supabase-js')
const multer = require('multer')
const exifr = require('exifr')
const fs = require('fs')
const path = require('path')
const { nanoid } = require('nanoid')
const webpush = require('web-push')

const app = express()
app.use(cors())
app.use(express.json({ limit: '5mb' }))
app.use(express.urlencoded({ extended: true }))
app.use(express.static('public'))

const supabaseUrl = process.env.SUPABASE_URL
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY
const hasSupabase = !!(supabaseUrl && supabaseAnonKey)
const IS_SERVERLESS = !!process.env.VERCEL || !!process.env.NOW_REGION

if (!hasSupabase) {
  console.error('Missing SUPABASE_URL or SUPABASE_ANON_KEY.')
  throw new Error('Supabase configuration missing.')
}

const supabase = createClient(supabaseUrl, supabaseAnonKey)

// In-memory state for SSE and Tracking (caching)
// We keep some in-memory state for performance and Realtime (SSE) shim
const sseClients = []
const trackingStateByUserId = new Map() // { userId: { active, lastPoint, stoppedAt, lastSeenAt } }
const statusStateByUserId = new Map() // { userId: { status, at, lat, lng } }

// Helper to get role
async function getUserRole(userId) {
  const { data } = await supabase.from('profiles').select('role').eq('id', userId).single()
  return data ? data.role : 'fisher'
}

// Auth Middleware
function auth(requiredRole) {
  return async (req, res, next) => {
    const authHeader = req.headers.authorization || ''
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null
    
    if (!token) return res.status(401).json({ error: 'Unauthorized' })

    try {
      const { data: { user }, error } = await supabase.auth.getUser(token)
      if (error || !user) throw error

      // Fetch profile for role
      const role = await getUserRole(user.id)
      req.user = { id: user.id, email: user.email, role }

      if (requiredRole) {
        const ok = Array.isArray(requiredRole) ? requiredRole.includes(role) : role === requiredRole
        if (!ok) return res.status(403).json({ error: 'Forbidden' })
      }
      next()
    } catch (e) {
      return res.status(401).json({ error: 'Invalid token' })
    }
  }
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
  const { email, password, name, role, barangay } = req.body
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' })

  // Supabase Auth SignUp
  const { data, error } = await supabase.auth.signUp({
    email,
    password,
    options: {
      data: { name, role: role || 'fisher', barangay } // Stored in user_metadata
    }
  })

  if (error) return res.status(400).json({ error: error.message })
  
  // Profile creation is handled by Trigger in DB, but we can ensure it exists or return info
  // Wait for trigger or just return
  res.json({ 
    token: data.session ? data.session.access_token : null, 
    user: { id: data.user.id, email: data.user.email, role: role || 'fisher' } 
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

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body
  const { data, error } = await supabase.auth.signInWithPassword({ email, password })
  
  if (error) return res.status(401).json({ error: error.message })
  
  const role = await getUserRole(data.user.id)
  res.json({ 
    token: data.session.access_token, 
    user: { id: data.user.id, email: data.user.email, role } 
  })
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
  const { species, netType, weightKg, lengthCm, gear, vessel, photoUrl, note, lat, lng, capturedAt } = req.body
  if (lat == null || lng == null) return res.status(400).json({ error: 'Missing coordinates' })
  
  const { data, error } = await supabase.from('catches').insert({
    user_id: req.user.id,
    species: species || 'unknown',
    net_type: netType || null,
    weight: weightKg || null,
    length: lengthCm || null,
    gear: gear || null,
    vessel: vessel || null,
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
    const { species, netType, weightKg, lengthCm, gear, vessel, note, lat, lng, capturedAt } = req.body
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

    const { data, error } = await supabase.from('catches').insert({
      user_id: req.user.id,
      species,
      weight: weightKg,
      length: lengthCm,
      net_type: netType,
      gear: gear,
      vessel: vessel,
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
  const { data, error } = await supabase.from('catches').select('*').eq('user_id', req.user.id)
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

app.get('/api/catches', auth('admin'), async (req, res) => {
  const { data: catches, error: cErr } = await supabase.from('catches').select('*, profiles(id, name, email)').order('recorded_at', { ascending: false })
  if (cErr) return res.status(400).json({ error: cErr.message })
  
  const list = (catches || []).map(c => ({
    ...c,
    user: c.profiles ? { id: c.profiles.id, name: c.profiles.name, email: c.profiles.email } : null,
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
  const { species, weightKg, lengthCm, gear, vessel, note } = req.body
  
  const updates = {}
  if (species !== undefined) updates.species = species
  if (weightKg !== undefined) updates.weight = weightKg
  if (lengthCm !== undefined) updates.length = lengthCm
  if (gear !== undefined) updates.gear = gear
  if (vessel !== undefined) updates.vessel = vessel
  if (note !== undefined) updates.notes = note

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

app.get('/api/admin/live_locations', auth('admin'), async (req, res) => {
  // Return last known state from memory shim for speed, or query DB?
  // Memory shim is better for "Live" dashboard
  const active = []
  trackingStateByUserId.forEach((v, k) => {
    if (v.active) active.push({ userId: k, ...v.lastPoint, active: true, lastSeenAt: v.lastSeenAt })
  })
  res.json(active)
})

app.get('/api/admin/status_history', auth('admin'), async (req, res) => {
  const { userId, limit } = req.query
  let q = supabase.from('status_events').select('*').order('at', { ascending: false }).limit(Number(limit)||50)
  if (userId) q = q.eq('user_id', userId)
  const { data, error } = await q
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

// SSE Endpoint
app.get('/api/admin/live', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream')
  res.setHeader('Cache-Control', 'no-cache')
  res.setHeader('Connection', 'keep-alive')
  res.flushHeaders()
  sseClients.push(res)
  req.on('close', () => {
    const idx = sseClients.indexOf(res)
    if (idx !== -1) sseClients.splice(idx, 1)
  })
})

if (IS_SERVERLESS) {
  module.exports = app
} else {
  const PORT = process.env.PORT || 3001
  app.listen(PORT, () => {
    console.log(`Supabase Server running on port ${PORT}`)
  })
}

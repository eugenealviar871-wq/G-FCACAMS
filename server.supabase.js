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

function normalizeText(value) {
  return value == null ? '' : String(value).trim()
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
function auth(requiredRole) {
  return async (req, res, next) => {
    const authHeader = req.headers.authorization || ''
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null
    const qToken = !token && req.query && req.query.token ? req.query.token : null
    const useToken = token || qToken
    
    if (!useToken) return res.status(401).json({ error: 'Unauthorized' })

    try {
      const { data: { user }, error } = await supabase.auth.getUser(useToken)
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
  const { data, error } = await supabase.from('vessels').select('*').order('created_at', { ascending: false })
  if (error) return res.status(400).json({ error: error.message })
  res.json(data || [])
})

app.get('/api/vessels/:id', auth(), async (req, res) => {
  const { data, error } = await supabase.from('vessels').select('*').eq('id', req.params.id).maybeSingle()
  if (error) return res.status(400).json({ error: error.message })
  if (!data) return res.status(404).json({ error: 'Vessel not found' })
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
    barangay
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

  const { data, error } = await supabase.from('vessels').update({
    vessel_registration_number,
    vessel_name,
    owner_name,
    barangay,
    updated_at: new Date().toISOString()
  }).eq('id', id).select().maybeSingle()
  if (error) return res.status(400).json({ error: error.message })
  if (!data) return res.status(404).json({ error: 'Vessel not found' })

  const { error: catchUpdateError } = await supabase.from('catches').update({
    vessel: vessel_name,
    vessel_registration_number,
    vessel_name,
    owner_name
  }).eq('vessel_id', id)
  if (catchUpdateError) return res.status(400).json({ error: catchUpdateError.message })

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
  const { data, error } = await supabase.auth.signInWithPassword({ email, password })
  
  if (error) return res.status(401).json({ error: error.message })
  
  const role = await getUserRole(data.user.id)
  const { data: profile } = await supabase
    .from('profiles')
    .select('name, barangay, vessel_name, fisher_id')
    .eq('id', data.user.id)
    .maybeSingle()
  res.json({ 
    token: data.session.access_token, 
    user: {
      id: data.user.id,
      name: (profile && profile.name) || data.user.user_metadata.name,
      email: data.user.email,
      role,
      barangay: profile && profile.barangay ? profile.barangay : null,
      vessel_name: profile && profile.vessel_name ? profile.vessel_name : null,
      fisher_id: profile && profile.fisher_id ? profile.fisher_id : null
    } 
  })
})

// --- DASHBOARD STATS ---
app.get('/api/dashboard/stats', auth(), async (req, res) => {
  try {
    const now = new Date()
    const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate()).toISOString()
    const startOfWeek = new Date(now.setDate(now.getDate() - 7)).toISOString()
    const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1).toISOString()

    // 1. Total catch today (kg)
    const { data: catchesToday } = await supabase.from('catches').select('weight').gte('recorded_at', startOfToday)
    const totalWeightToday = (catchesToday || []).reduce((sum, c) => sum + (Number(c.weight) || 0), 0)

    // 2. Active vessels (from in-memory shim)
    let activeVessels = 0
    trackingStateByUserId.forEach(v => { if (v.active) activeVessels++ })

    // 3. Total coastal activities this week
    const { count: activitiesWeek } = await supabase.from('activity_logs').select('*', { count: 'exact', head: true }).gte('created_at', startOfWeek)

    // 4. Top 3 species this month
    const { data: monthlyCatches } = await supabase.from('catches').select('species').gte('recorded_at', startOfMonth)
    const speciesCounts = (monthlyCatches || []).reduce((acc, c) => {
      acc[c.species] = (acc[c.species] || 0) + 1
      return acc
    }, {})
    const topSpecies = Object.entries(speciesCounts)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 3)
      .map(([name, count]) => ({ name, count }))

    // 5. Monthly catch trend (last 6 months)
    const trend = []
    for (let i = 5; i >= 0; i--) {
      const d = new Date()
      d.setMonth(d.getMonth() - i)
      const mStart = new Date(d.getFullYear(), d.getMonth(), 1).toISOString()
      const mEnd = new Date(d.getFullYear(), d.getMonth() + 1, 0, 23, 59, 59).toISOString()
      const { data: mData } = await supabase.from('catches').select('weight').gte('recorded_at', mStart).lte('recorded_at', mEnd)
      const mWeight = (mData || []).reduce((sum, c) => sum + (Number(c.weight) || 0), 0)
      trend.push({ month: d.toLocaleString('default', { month: 'short' }), weight: mWeight })
    }

    res.json({
      totalWeightToday,
      activeVessels,
      activitiesWeek: activitiesWeek || 0,
      topSpecies,
      trend
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
  const { data: catches, error: cErr } = await supabase.from('catches').select('*, profiles(id, name, email), vessels(*)').order('recorded_at', { ascending: false })
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

app.get('/api/live_locations', auth(), async (req, res) => {
  // Return last known state from memory shim for speed
  const active = []
  trackingStateByUserId.forEach((v, k) => {
    if (v.active) active.push({ userId: k, ...v.lastPoint, active: true, lastSeenAt: v.lastSeenAt })
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

app.get('/api/users', auth(), async (req, res) => {
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
  let q = supabase.from('status_events').select('*').order('at', { ascending: false }).limit(Number(limit)||50)
  if (userId) q = q.eq('user_id', userId)
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

// SSE Endpoint
app.get('/api/admin/live', auth(['admin','inspector']), (req, res) => {
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
} else if (require.main === module) {
  const PORT = process.env.PORT || 3001
  app.listen(PORT, () => {
    console.log(`Supabase Server running on port ${PORT}`)
  })
} else {
  module.exports = app
}

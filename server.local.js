const express = require('express')
const cors = require('cors')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const low = require('lowdb')
const FileSync = require('lowdb/adapters/FileSync')
const { nanoid } = require('nanoid')
const path = require('path')
const fs = require('fs')
const https = require('https')
const multer = require('multer')
const exifr = require('exifr')
const nodemailer = require('nodemailer')
const webpush = require('web-push')
const os = require('os')

const app = express()
app.use(cors())
app.use(express.json({ limit: '2mb' }))
app.use(express.urlencoded({ extended: true }))

process.on('unhandledRejection', (e) => { try { console.error('unhandledRejection', e) } catch {} })
process.on('uncaughtException', (e) => { try { console.error('uncaughtException', e) } catch {} })

const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me'

const IS_SERVERLESS = !!process.env.VERCEL || !!process.env.NOW_REGION
const DATA_DIR = IS_SERVERLESS ? path.join('/tmp', 'data') : path.join(__dirname, 'data')
const UPLOAD_DIR = IS_SERVERLESS ? path.join('/tmp', 'uploads') : path.join(__dirname, 'uploads')
try { fs.mkdirSync(DATA_DIR, { recursive: true }); fs.mkdirSync(UPLOAD_DIR, { recursive: true }) } catch {}
const usersAdapter = new FileSync(path.join(DATA_DIR, 'users.json'))
const catchesAdapter = new FileSync(path.join(DATA_DIR, 'catches.json'))
const tracksAdapter = new FileSync(path.join(DATA_DIR, 'tracks.json'))
const speciesAdapter = new FileSync(path.join(DATA_DIR, 'species.json'))
const zonesAdapter = new FileSync(path.join(DATA_DIR, 'zones.json'))
const alertsAdapter = new FileSync(path.join(DATA_DIR, 'alerts.json'))
const pushAdapter = new FileSync(path.join(DATA_DIR, 'push.json'))
const activityAdapter = new FileSync(path.join(DATA_DIR, 'activity_logs.json'))
const imagesAdapter = new FileSync(path.join(DATA_DIR, 'images.json'))
const protectedAreasAdapter = new FileSync(path.join(DATA_DIR, 'protected_areas.json'))
const statusAdapter = new FileSync(path.join(DATA_DIR, 'status_events.json'))

const usersDb = low(usersAdapter)
const catchesDb = low(catchesAdapter)
const tracksDb = low(tracksAdapter)
const speciesDb = low(speciesAdapter)
const zonesDb = low(zonesAdapter)
const alertsDb = low(alertsAdapter)
const pushDb = low(pushAdapter)
const activityDb = low(activityAdapter)
const imagesDb = low(imagesAdapter)
const protectedAreasDb = low(protectedAreasAdapter)
const statusDb = low(statusAdapter)

usersDb.defaults({ users: [] }).write()
catchesDb.defaults({ catches: [] }).write()
tracksDb.defaults({ tracks: [] }).write()
speciesDb.defaults({ species: [] }).write()
zonesDb.defaults({ zones: [] }).write()
alertsDb.defaults({ alerts: [] }).write()
pushDb.defaults({ subscriptions: [] }).write()
activityDb.defaults({ activity_logs: [] }).write()
imagesDb.defaults({ images: [] }).write()
protectedAreasDb.defaults({ protected_areas: [] }).write()
statusDb.defaults({ status_events: [] }).write()

const ACTIVE_TTL_MS = 35000
const trackingStateByUserId = new Map()
const statusStateByUserId = new Map()
function normalizeStatusValue(v) {
  const s = String(v || '').trim().toLowerCase()
  if (s === 'port' || s === 'in_port' || s === 'in port') return 'port'
  if (s === 'transit' || s === 'in_transit' || s === 'in transit') return 'transit'
  return null
}
function setUserStatusState(userId, next) {
  if (!userId) return
  const prev = statusStateByUserId.get(userId) || {}
  statusStateByUserId.set(userId, { ...prev, ...next, userId })
}
function getUserStatusState(userId) {
  if (!userId) return null
  return statusStateByUserId.get(userId) || null
}
function getUserEffectiveStatus(userId) {
  const st = getUserStatusState(userId)
  if (st && st.status) return st
  const tr = trackingStateByUserId.get(userId)
  if (tr && tr.active && tr.lastSeenAt) return { userId, status: 'transit', at: new Date(tr.lastSeenAt).toISOString(), lat: tr.lastPoint ? tr.lastPoint.lat : null, lng: tr.lastPoint ? tr.lastPoint.lng : null }
  return { userId, status: null, at: null, lat: null, lng: null }
}

try {
  const list = statusDb.get('status_events').value() || []
  const byUser = new Map()
  list.forEach(e => {
    const userId = e && e.userId ? String(e.userId) : null
    if (!userId) return
    const at = e.at || e.recordedAt || null
    const t = at ? new Date(at).getTime() : NaN
    if (!Number.isFinite(t)) return
    const prev = byUser.get(userId)
    if (!prev || t >= prev._t) byUser.set(userId, { ...e, _t: t })
  })
  byUser.forEach((e, userId) => {
    const { _t, ...rest } = e
    setUserStatusState(userId, { status: normalizeStatusValue(rest.status), at: rest.at || rest.recordedAt || new Date(_t).toISOString(), lat: rest.lat != null ? Number(rest.lat) : null, lng: rest.lng != null ? Number(rest.lng) : null })
  })
} catch {}
function markUserTracking(userId, point) {
  if (!userId) return
  const prev = trackingStateByUserId.get(userId) || {}
  const lastSeenAt = Date.now()
  trackingStateByUserId.set(userId, { ...prev, userId, active: true, lastSeenAt, lastPoint: point || prev.lastPoint || null, stoppedAt: null })
}
function stopUserTracking(userId) {
  if (!userId) return
  const prev = trackingStateByUserId.get(userId) || { userId }
  trackingStateByUserId.set(userId, { ...prev, userId, active: false, stoppedAt: Date.now() })
}
function getUserTrackingStatus(userId, recordedAt) {
  const now = Date.now()
  const st = trackingStateByUserId.get(userId)
  if (st) {
    if (st.active) return { active: true, lastSeenAt: st.lastSeenAt }
    if (st.stoppedAt) return { active: false, lastSeenAt: st.stoppedAt }
  }
  const t = recordedAt ? new Date(recordedAt).getTime() : NaN
  if (Number.isFinite(t) && now - t <= ACTIVE_TTL_MS) return { active: true, lastSeenAt: t }
  return { active: false, lastSeenAt: Number.isFinite(t) ? t : null }
}

const initialSpecies = [
  'Galunggong (Mackerel Scad)',
  'Matambaka (Bigeye Scad)',
  'Tamban (Sardines)',
  'Alumahan (Indian mackerel)',
  'Tulingan (Skipjack tuna)',
  'Tuna (Yellowfin, Bigeye)',
  'Bangsi (Flying fish)',
  'Dorado / Mahi-mahi',
  'Marlin / Sailfish',
  'Lapu-lapu (Grouper)',
  'Maya-maya (Snapper)',
  'Danggit (Rabbitfish)',
  'Sapsap',
  'Alimango (Mud crab)',
  'Alimasag (Blue swimming crab)',
  'Talangka (Small crabs, for bagoong)',
  'Pusit (Squid)',
  'Nokus (Cuttlefish)'
]
try {
  const cur = speciesDb.get('species').value() || []
  if (cur.length === 0) speciesDb.set('species', initialSpecies).write()
} catch (e) {
  console.error('Species DB Init Error:', e.message)
}
const hasAdmin = usersDb.get('users').find(u => u.role === 'admin').value()
if (!hasAdmin) {
  const adminEmail = process.env.ADMIN_EMAIL || 'admin@local.test'
  const adminPass = process.env.ADMIN_PASSWORD || 'admin123'
  const admin = { id: nanoid(), name: 'Administrator', email: adminEmail, pass: bcrypt.hashSync(adminPass, 10), role: 'admin', createdAt: new Date().toISOString() }
  usersDb.get('users').push(admin).write()
  console.log(`Seeded admin account: ${adminEmail} / ${adminPass}`)
}

const MAPBOX_TOKEN = process.env.MAPBOX_TOKEN || ''
const VAPID_PUBLIC = process.env.VAPID_PUBLIC || ''
const VAPID_PRIVATE = process.env.VAPID_PRIVATE || ''
if (VAPID_PUBLIC && VAPID_PRIVATE) {
  webpush.setVapidDetails('mailto:admin@example.com', VAPID_PUBLIC, VAPID_PRIVATE)
}

function createToken(user) {
  return jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '7d' })
}

function auth(requiredRole) {
  return (req, res, next) => {
    const authHeader = req.headers.authorization || ''
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null
    const qToken = !token && req.query && req.query.token ? req.query.token : null
    const useToken = token || qToken
    if (!useToken) return res.status(401).json({ error: 'Unauthorized' })
    try {
      const payload = jwt.verify(useToken, JWT_SECRET)
      req.user = payload
      if (requiredRole) {
        const ok = Array.isArray(requiredRole) ? requiredRole.includes(payload.role) : payload.role === requiredRole
        if (!ok) return res.status(403).json({ error: 'Forbidden' })
      }
      next()
    } catch (e) {
      return res.status(401).json({ error: 'Invalid token' })
    }
  }
}

app.post('/api/auth/register', async (req, res) => {
  let { name, email, password, role, barangay } = req.body
  if (!name || !email || !password) return res.status(400).json({ error: 'Missing fields' })
  email = String(email).trim().toLowerCase()
  const exists = usersDb.get('users').find(u => String(u.email||'').trim().toLowerCase() === email).value()
  if (exists) return res.status(409).json({ error: 'Email already registered' })
  const hash = bcrypt.hashSync(password, 10)
  const roleSafe = ['admin','inspector','fisher','researcher'].includes((role||'').toLowerCase()) ? role.toLowerCase() : 'fisher'
  const user = { id: nanoid(), name, email, pass: hash, role: roleSafe, barangay: barangay || null, createdAt: new Date().toISOString() }
  usersDb.get('users').push(user).write()
  const token = createToken(user)
  res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role, barangay: user.barangay } })
})

app.post('/api/auth/login', async (req, res) => {
  let { email, password } = req.body
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' })
  email = String(email).trim().toLowerCase()
  const list = usersDb.get('users').value()
  const user = list.find(u => String(u.email||'').trim().toLowerCase() === email)
  if (!user) return res.status(401).json({ error: 'Invalid credentials' })
  const ok = bcrypt.compareSync(password, user.pass)
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' })
  const token = createToken(user)
  res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } })
})

// Public endpoint to install the first admin (browser-based setup)
app.post('/api/public/install_admin', (req, res) => {
  const existingAdmins = usersDb.get('users').filter(u => u.role === 'admin').value()
  if ((existingAdmins||[]).length > 0) return res.status(400).json({ error: 'Admin already exists' })
  let { email, password, name } = req.body
  email = String(email || process.env.ADMIN_EMAIL || 'admin@local.test').trim().toLowerCase()
  password = String(password || process.env.ADMIN_PASSWORD || 'admin123')
  name = String(name || 'Administrator')
  if (!email || !password) return res.status(400).json({ error: 'Missing email/password' })
  const exists = usersDb.get('users').find(u => String(u.email||'').trim().toLowerCase() === email).value()
  if (exists) return res.status(409).json({ error: 'Email exists' })
  const hash = bcrypt.hashSync(password, 10)
  const user = { id: nanoid(), name, email, pass: hash, role: 'admin', createdAt: new Date().toISOString() }
  usersDb.get('users').push(user).write()
  res.json({ ok: true, user: { id: user.id, name: user.name, email: user.email, role: user.role } })
})

app.post('/api/catches', auth(), async (req, res) => {
  const { species, netType, weightKg, lengthCm, gear, vessel, photoUrl, note, lat, lng, capturedAt } = req.body
  if (lat == null || lng == null) return res.status(400).json({ error: 'Missing coordinates' })
  const catchItem = {
    id: nanoid(),
    userId: req.user.id,
    species: species || 'unknown',
    netType: netType || null,
    weightKg: weightKg || null,
    lengthCm: lengthCm || null,
    gear: gear || null,
    vessel: vessel || null,
    photoUrl: photoUrl || null,
    note: note || null,
    lat, lng,
    capturedAt: capturedAt || new Date().toISOString(),
    createdAt: new Date().toISOString()
  }
  catchesDb.get('catches').push(catchItem).write()
  broadcastCatch(catchItem)
  try {
    const zones = zonesDb.get('zones').value()
    const areas = protectedAreasDb.get('protected_areas').value()
    const turf = require('@turf/turf')
    const pt = turf.point([lng, lat])
    const polys = [
      ...zones.map(z => z.geometry ? { type: 'Feature', geometry: z.geometry } : null).filter(Boolean),
      ...areas.map(a => a.geom ? { type: 'Feature', geometry: a.geom } : null).filter(Boolean)
    ]
    if (polys.some(poly => { try { return turf.booleanPointInPolygon(pt, poly) } catch { return false } })) {
      const u = usersDb.get('users').find({ id: req.user.id }).value()
      const alert = { id: nanoid(), type: 'Restricted Catch', status: 'pending', note: null, userId: req.user.id, userName: u ? u.name : null, lat, lng, zoneId: null, recordedAt: new Date().toISOString() }
      alertsDb.get('alerts').push(alert).write()
      broadcastAlert(alert)
    }
  } catch {}
  res.json(catchItem)
})

// Photo upload with EXIF GPS fallback
const upload = multer({ dest: UPLOAD_DIR })
app.post('/api/catches/upload', auth(), upload.single('photo'), async (req, res) => {
  try {
    const { species, netType, weightKg, lengthCm, gear, vessel, note, lat, lng, capturedAt } = req.body
    let latNum = lat != null ? parseFloat(lat) : null
    let lngNum = lng != null ? parseFloat(lng) : null
    if ((latNum == null || lngNum == null) && req.file) {
      const exif = await exifr.gps(req.file.path).catch(() => null)
      if (exif && exif.latitude && exif.longitude) { latNum = exif.latitude; lngNum = exif.longitude }
    }
    if (latNum == null || lngNum == null) return res.status(400).json({ error: 'Missing coordinates' })
    const item = {
      id: nanoid(), userId: req.user.id,
      species: species || 'unknown', netType: netType || null, weightKg: weightKg ? parseFloat(weightKg) : null,
      lengthCm: lengthCm ? parseFloat(lengthCm) : null, gear: gear || null, vessel: vessel || null,
      photoUrl: req.file ? `/uploads/${req.file.filename}` : null,
      note: note || null, lat: latNum, lng: lngNum,
      capturedAt: capturedAt || new Date().toISOString(), createdAt: new Date().toISOString()
    }
    catchesDb.get('catches').push(item).write()
    broadcastCatch(item)
    if (req.file) {
      const exif = await exifr.parse(req.file.path).catch(() => null)
      const img = { id: nanoid(), catch_id: item.id, bucket_key: `/uploads/${req.file.filename}`, exif: exif || null, created_at: new Date().toISOString() }
      imagesDb.get('images').push(img).write()
    }
    res.json(item)
  } catch (e) {
    res.status(500).json({ error: 'Upload failed' })
  }
})

app.get('/api/catches/me', auth(), async (req, res) => {
  const items = catchesDb.get('catches').filter(c => c.userId === req.user.id).value()
  res.json(items)
})

app.get('/api/catches', auth('admin'), async (req, res) => {
  const allC = catchesDb.get('catches').value()
  const allU = usersDb.get('users').value()
  const list = allC.map(c => ({
    ...c,
    user: allU.find(u => u.id === c.userId) ? { id: c.userId, name: allU.find(u => u.id === c.userId).name, email: allU.find(u => u.id === c.userId).email } : null
  }))
  res.json(list)
})

app.patch('/api/admin/catches/:id', auth('admin'), async (req, res) => {
  const id = req.params.id
  const allowed = ['species','weightKg','lengthCm','gear','vessel','note']
  const updates = {}
  allowed.forEach(k => { if (req.body[k] !== undefined) updates[k] = req.body[k] })
  const exists = catchesDb.get('catches').find({ id }).value(); if (!exists) return res.status(404).json({ error: 'Not found' })
  catchesDb.get('catches').find({ id }).assign(updates).write(); res.json({ ok: true })
})

app.delete('/api/admin/catches/:id', auth('admin'), async (req, res) => {
  const id = req.params.id
  const exists = catchesDb.get('catches').find({ id }).value(); if (!exists) return res.status(404).json({ error: 'Not found' })
  catchesDb.set('catches', catchesDb.get('catches').filter(c => c.id !== id).value()).write(); res.json({ ok: true })
})

app.post('/api/track', auth(), async (req, res) => {
  const { lat, lng, accuracy, speed, heading, recordedAt } = req.body
  const latNum = lat != null ? Number(lat) : NaN
  const lngNum = lng != null ? Number(lng) : NaN
  if (!Number.isFinite(latNum) || !Number.isFinite(lngNum)) return res.status(400).json({ error: 'Missing coordinates' })
  const point = {
    id: nanoid(), userId: req.user.id, lat: latNum, lng: lngNum,
    accuracy: accuracy != null && accuracy !== '' ? Number(accuracy) : null,
    speed: speed != null && speed !== '' ? Number(speed) : null,
    heading: heading != null && heading !== '' ? Number(heading) : null,
    recordedAt: recordedAt || new Date().toISOString()
  }
  const u = usersDb.get('users').find({ id: req.user.id }).value()
  const st_before = getUserTrackingStatus(req.user.id, point.recordedAt)
  
  tracksDb.get('tracks').push(point).write()
  markUserTracking(req.user.id, point)
  
  const st_after = getUserTrackingStatus(req.user.id, point.recordedAt)
  const statusState = getUserEffectiveStatus(req.user.id)
  broadcastTrack({ type: 'track', ...point, active: st_after.active, lastSeenAt: st_after.lastSeenAt ? new Date(st_after.lastSeenAt).toISOString() : null, status: statusState.status, statusAt: statusState.at, user: u ? { id: u.id, name: u.name, email: u.email } : null })

  // Notification: User becomes Active
  if (!st_before.active && st_after.active) {
    const alert = { id: nanoid(), type: 'Status: Active', status: 'pending', note: null, userId: req.user.id, userName: u ? u.name : null, lat: latNum, lng: lngNum, zoneId: null, recordedAt: new Date().toISOString() }
    alertsDb.get('alerts').push(alert).write()
    broadcastAlert(alert)
  }

  const zones = zonesDb.get('zones').value()
  const areas = protectedAreasDb.get('protected_areas').value()
  const turf = require('@turf/turf')
  const pt = turf.point([lngNum, latNum])
  const polygons = [
    ...zones.map(z => ({ id: z.id, geometry: z.geometry })),
    ...areas.map(a => ({ id: a.id, geometry: a.geom }))
  ]
  polygons.forEach(z => {
    try {
      const poly = z.geometry ? { type: 'Feature', geometry: z.geometry } : null
      if (!poly) return
      const inside = turf.booleanPointInPolygon(pt, poly)
      if (inside) {
        const u = usersDb.get('users').find({ id: req.user.id }).value()
        const alert = { id: nanoid(), type: 'Protected Zone', status: 'pending', note: null, userId: req.user.id, userName: u ? u.name : null, lat: latNum, lng: lngNum, zoneId: z.id || null, recordedAt: new Date().toISOString() }
        alertsDb.get('alerts').push(alert).write()
        broadcastAlert(alert)
      }
    } catch {}
  })
  res.json({ ok: true })
})

app.post('/api/status', auth(), async (req, res) => {
  const status = normalizeStatusValue(req.body && req.body.status)
  if (!status) return res.status(400).json({ error: 'Invalid status' })
  let latNum = req.body && req.body.lat != null ? Number(req.body.lat) : NaN
  let lngNum = req.body && req.body.lng != null ? Number(req.body.lng) : NaN
  const atIso = (req.body && req.body.at) ? String(req.body.at) : new Date().toISOString()
  const atMs = new Date(atIso).getTime()
  if (!Number.isFinite(atMs)) return res.status(400).json({ error: 'Invalid timestamp' })
  if (status === 'port' && (!Number.isFinite(latNum) || !Number.isFinite(lngNum))) return res.status(400).json({ error: 'Missing coordinates' })

  if (status === 'transit' && (!Number.isFinite(latNum) || !Number.isFinite(lngNum))) {
    const st = trackingStateByUserId.get(req.user.id)
    const lp = st && st.lastPoint ? st.lastPoint : null
    if (lp && lp.lat != null && lp.lng != null) {
      latNum = Number(lp.lat)
      lngNum = Number(lp.lng)
    }
  }

  const item = { id: nanoid(), userId: req.user.id, status, at: new Date(atMs).toISOString(), lat: Number.isFinite(latNum) ? latNum : null, lng: Number.isFinite(lngNum) ? lngNum : null }
  statusDb.get('status_events').push(item).write()
  setUserStatusState(req.user.id, { status, at: item.at, lat: item.lat, lng: item.lng })

  // Notification: Status Change
  try {
    const u = usersDb.get('users').find({ id: req.user.id }).value()
    const alertType = status === 'port' ? 'Status: In Port' : 'Status: In Transit'
    const alert = { 
      id: nanoid(), 
      type: alertType, 
      status: 'pending', 
      note: null, 
      userId: req.user.id, 
      userName: u ? u.name : null, 
      lat: item.lat || 0, 
      lng: item.lng || 0, 
      zoneId: null, 
      recordedAt: item.at 
    }
    alertsDb.get('alerts').push(alert).write()
    broadcastAlert(alert)
  } catch {}

  if (status === 'port') {
    stopUserTracking(req.user.id)
    const st = trackingStateByUserId.get(req.user.id)
    if (st) trackingStateByUserId.set(req.user.id, { ...st, active: false })
    const last = st && st.lastPoint ? st.lastPoint : null
    const stopAt = item.at
    broadcastTrack({
      type: 'track_stop',
      userId: req.user.id,
      at: stopAt,
      lat: item.lat != null ? item.lat : (last && last.lat != null ? last.lat : undefined),
      lng: item.lng != null ? item.lng : (last && last.lng != null ? last.lng : undefined),
      accuracy: last && last.accuracy != null ? last.accuracy : undefined,
      speed: last && last.speed != null ? last.speed : undefined,
      heading: last && last.heading != null ? last.heading : undefined,
      recordedAt: last && last.recordedAt ? last.recordedAt : stopAt,
      active: false,
      lastSeenAt: stopAt
    })
  }

  broadcastStatus({ type: 'status', ...item })
  res.json({ ok: true, item })
})

app.post('/api/track/stop', auth(), async (req, res) => {
  stopUserTracking(req.user.id)
  const st = trackingStateByUserId.get(req.user.id)
  const atIso = new Date((st && st.stoppedAt) ? st.stoppedAt : Date.now()).toISOString()
  const last = st && st.lastPoint ? st.lastPoint : null
  const statusState = getUserEffectiveStatus(req.user.id)
  broadcastTrack({
    type: 'track_stop',
    userId: req.user.id,
    at: atIso,
    lat: last && last.lat != null ? last.lat : undefined,
    lng: last && last.lng != null ? last.lng : undefined,
    accuracy: last && last.accuracy != null ? last.accuracy : undefined,
    speed: last && last.speed != null ? last.speed : undefined,
    heading: last && last.heading != null ? last.heading : undefined,
    recordedAt: last && last.recordedAt ? last.recordedAt : atIso,
    active: false,
    lastSeenAt: atIso,
    status: statusState.status,
    statusAt: statusState.at
  })
  res.json({ ok: true })
})

app.get('/api/status/me', auth(), async (req, res) => {
  const list = statusDb.get('status_events').filter(e => e.userId === req.user.id).value()
  const out = (list || []).slice().sort((a, b) => new Date(b.at || 0) - new Date(a.at || 0))
  res.json(out)
})

app.get('/api/track/me', auth(), async (req, res) => {
  const points = tracksDb.get('tracks').filter(t => t.userId === req.user.id).value()
  res.json(points)
})

app.get('/api/admin/users', auth('admin'), async (req, res) => {
  const all = usersDb.get('users').value()
  res.json(all.map(u => ({ id: u.id, name: u.name, email: u.email, role: u.role, barangay: u.barangay || null, createdAt: u.createdAt })))
})

app.post('/api/admin/users', auth('admin'), async (req, res) => {
  let { name, email, password, role } = req.body
  if (!name || !email || !password) return res.status(400).json({ error: 'Missing fields' })
  email = String(email).trim().toLowerCase()
  const exists = usersDb.get('users').find(u => String(u.email||'').trim().toLowerCase() === email).value()
  if (exists) return res.status(409).json({ error: 'Email exists' })
  const roleSafe = ['admin','inspector','fisher','researcher'].includes((role||'').toLowerCase()) ? role.toLowerCase() : 'fisher'
  const user = { id: nanoid(), name, email, pass: bcrypt.hashSync(password, 10), role: roleSafe, createdAt: new Date().toISOString() }
  usersDb.get('users').push(user).write()
  res.json({ id: user.id, name: user.name, email: user.email, role: user.role, createdAt: user.createdAt })
})

app.patch('/api/admin/users/:id/role', auth('admin'), async (req, res) => {
  const id = req.params.id
  const { role } = req.body
  const valid = ['admin','inspector','fisher','researcher']
  if (!valid.includes((role||'').toLowerCase())) return res.status(400).json({ error: 'Invalid role' })
  const user = usersDb.get('users').find({ id }).value()
  if (!user) return res.status(404).json({ error: 'User not found' })
  usersDb.get('users').find({ id }).assign({ role: role.toLowerCase() }).write()
  res.json({ ok: true })
})

app.delete('/api/admin/users/:id', auth('admin'), async (req, res) => {
  const id = req.params.id
  const user = usersDb.get('users').find({ id }).value(); if (!user) return res.status(404).json({ error: 'Not found' })
  const admins = usersDb.get('users').filter(u => u.role === 'admin').value()
  if (user.role === 'admin' && admins.length <= 1) return res.status(400).json({ error: 'Cannot delete the last admin' })
  const userCatches = catchesDb.get('catches').filter(c => c.userId === id).value()
  const catchIds = userCatches.map(c => c.id)
  usersDb.set('users', usersDb.get('users').filter(u => u.id !== id).value()).write()
  catchesDb.set('catches', catchesDb.get('catches').filter(c => c.userId !== id).value()).write()
  tracksDb.set('tracks', tracksDb.get('tracks').filter(t => t.userId !== id).value()).write()
  activityDb.set('activity_logs', activityDb.get('activity_logs').filter(a => a.user_id !== id).value()).write()
  alertsDb.set('alerts', alertsDb.get('alerts').filter(a => a.userId !== id).value()).write()
  imagesDb.set('images', imagesDb.get('images').filter(i => !catchIds.includes(i.catch_id)).value()).write()
  pushDb.set('subscriptions', pushDb.get('subscriptions').filter(s => s.userId !== id).value()).write()
  res.json({ ok: true })
})

app.get('/api/admin/tracks', auth('admin'), async (req, res) => {
  const pts = tracksDb.get('tracks').value(); const us = usersDb.get('users').value()
  const points = pts.map(p => ({
    ...p,
    user: us.find(u => u.id === p.userId) ? { id: p.userId, name: us.find(u => u.id === p.userId).name, email: us.find(u => u.id === p.userId).email } : null
  }))
  res.json(points)
})
app.get('/api/admin/status_history', auth(['admin','inspector']), async (req, res) => {
  const userId = req.query && req.query.userId != null ? String(req.query.userId) : null
  const limitRaw = req.query && req.query.limit != null ? Number(req.query.limit) : 200
  const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(1000, Math.floor(limitRaw))) : 200
  const us = usersDb.get('users').value()
  let list = statusDb.get('status_events').value() || []
  if (userId) list = list.filter(e => String(e.userId) === userId)
  list = list.slice().sort((a, b) => new Date(b.at || 0) - new Date(a.at || 0)).slice(0, limit)
  const out = list.map(e => {
    const u = us.find(x => x.id === e.userId)
    return { ...e, user: u ? { id: u.id, name: u.name, email: u.email } : null }
  })
  res.json(out)
})
app.get('/api/admin/live_locations', auth(['admin','inspector']), (req, res) => {
  const pts = tracksDb.get('tracks').value()
  const us = usersDb.get('users').value()

  const latestByUserId = new Map()
  statusStateByUserId.forEach((st, userId) => {
    if (!st || !userId) return
    const lat = st.lat != null ? Number(st.lat) : NaN
    const lng = st.lng != null ? Number(st.lng) : NaN
    if (!Number.isFinite(lat) || !Number.isFinite(lng)) return
    const at = st.at ? String(st.at) : null
    const t = at ? new Date(at).getTime() : NaN
    if (!Number.isFinite(t)) return
    latestByUserId.set(String(userId), { userId: String(userId), lat, lng, accuracy: null, speed: null, heading: null, recordedAt: at, _t: t })
  })
  pts.forEach(p => {
    const userId = p && p.userId ? String(p.userId) : null
    if (!userId) return
    const recordedAt = p.recordedAt || null
    const t = recordedAt ? new Date(recordedAt).getTime() : NaN
    if (!Number.isFinite(t)) return
    const cur = latestByUserId.get(userId)
    if (!cur || t > cur._t) latestByUserId.set(userId, { ...p, _t: t })
  })

  const out = Array.from(latestByUserId.values())
    .sort((a, b) => b._t - a._t)
    .map(p => {
      const u = us.find(x => x.id === p.userId)
      const { _t, ...rest } = p
      const st = getUserTrackingStatus(p.userId, rest.recordedAt)
      const statusState = getUserEffectiveStatus(p.userId)
      const active = statusState.status === 'transit' ? st.active : false
      const lastSeenAt = active ? (st.lastSeenAt ? new Date(st.lastSeenAt).toISOString() : null) : (statusState.at || (st.lastSeenAt ? new Date(st.lastSeenAt).toISOString() : null))
      return { ...rest, active, lastSeenAt, status: statusState.status, statusAt: statusState.at, user: u ? { id: u.id, name: u.name, email: u.email } : null }
    })

  res.json(out)
})
app.delete('/api/admin/tracks/:id', auth('admin'), (req, res) => {
  const id = req.params.id
  const exists = tracksDb.get('tracks').find({ id }).value()
  if (!exists) return res.status(404).json({ error: 'Not found' })
  tracksDb.set('tracks', tracksDb.get('tracks').filter(t => t.id !== id).value()).write()
  res.json({ ok: true })
})

// Species management
app.get('/api/admin/species', auth('admin'), (req, res) => {
  res.json(speciesDb.get('species').value())
})
app.get('/api/species', (req, res) => {
  res.json(speciesDb.get('species').value())
})
app.post('/api/admin/species', auth('admin'), (req, res) => {
  const { name } = req.body; if (!name) return res.status(400).json({ error: 'Name required' })
  const list = speciesDb.get('species').value()
  if (list.includes(name)) return res.status(409).json({ error: 'Exists' })
  speciesDb.get('species').push(name).write(); res.json({ ok: true })
})
app.delete('/api/admin/species', auth('admin'), (req, res) => {
  const { name } = req.body; speciesDb.set('species', speciesDb.get('species').filter(s => s !== name).value()).write(); res.json({ ok: true })
})

// Protected zones GeoJSON management (FeatureCollection of Polygons)
app.get('/api/admin/zones', auth('admin'), (req, res) => {
  res.json(zonesDb.get('zones').value())
})
app.post('/api/admin/zones', auth('admin'), (req, res) => {
  const { zone } = req.body
  if (!zone || !zone.type || zone.type !== 'Feature' || !zone.geometry) return res.status(400).json({ error: 'Invalid GeoJSON Feature' })
  const z = { ...zone, id: nanoid() }
  zonesDb.get('zones').push(z).write(); res.json(z)
})
app.delete('/api/admin/zones/:id', auth('admin'), (req, res) => {
  const id = req.params.id
  zonesDb.set('zones', zonesDb.get('zones').filter(z => z.id !== id).value()).write(); res.json({ ok: true })
})

// Alerts listing
app.get('/api/admin/alerts', auth(['admin','inspector']), (req, res) => {
  const list = alertsDb.get('alerts').value()
  const us = usersDb.get('users').value()
  const mapped = list.map(a => ({ ...a, user: us.find(u => u.id === a.userId) ? { id: a.userId, name: us.find(u => u.id === a.userId).name, email: us.find(u => u.id === a.userId).email } : null }))
  res.json(mapped)
})
app.patch('/api/admin/alerts/:id', auth(['admin','inspector']), (req, res) => {
  const id = req.params.id
  const { status, note } = req.body
  const a = alertsDb.get('alerts').find({ id }).value(); if (!a) return res.status(404).json({ error: 'Not found' })
  const next = { status: status || a.status, note: note ?? a.note }
  alertsDb.get('alerts').find({ id }).assign(next).write(); res.json({ ok: true })
})
app.delete('/api/admin/alerts/:id', auth('admin'), (req, res) => {
  const id = req.params.id
  const exists = alertsDb.get('alerts').find({ id }).value()
  if (!exists) return res.status(404).json({ error: 'Not found' })
  alertsDb.set('alerts', alertsDb.get('alerts').filter(a => a.id !== id).value()).write()
  res.json({ ok: true })
})
app.post('/api/alerts', auth(), (req, res) => {
  const { type, lat, lng, note } = req.body
  if (!type || lat == null || lng == null) return res.status(400).json({ error: 'Missing fields' })
  const u = usersDb.get('users').find({ id: req.user.id }).value()
  const a = { id: nanoid(), type: String(type), status: 'pending', note: note || null, userId: req.user.id, userName: u ? u.name : null, lat: parseFloat(lat), lng: parseFloat(lng), recordedAt: new Date().toISOString() }
  alertsDb.get('alerts').push(a).write()
  broadcastAlert(a)
  res.json(a)
})
app.post('/api/alerts/create', auth(), (req, res) => {
  const { type, lat, lng, note } = req.body
  if (!type || lat == null || lng == null) return res.status(400).json({ error: 'Missing fields' })
  const u = usersDb.get('users').find({ id: req.user.id }).value()
  const a = { id: nanoid(), type: String(type), status: 'pending', note: note || null, userId: req.user.id, userName: u ? u.name : null, lat: parseFloat(lat), lng: parseFloat(lng), recordedAt: new Date().toISOString() }
  alertsDb.get('alerts').push(a).write()
  broadcastAlert(a)
  res.json(a)
})
app.get('/api/test_alerts', (req, res) => { res.json({ ok: true }) })

app.post('/api/push/subscribe', auth(), (req, res) => {
  const sub = req.body
  if (!sub || !sub.endpoint) return res.status(400).json({ error: 'Invalid subscription' })
  const exists = pushDb.get('subscriptions').find(s => s.endpoint === sub.endpoint).value()
  if (!exists) pushDb.get('subscriptions').push({ ...sub, userId: req.user.id }).write()
  res.json({ ok: true })
})
app.post('/api/admin/notify', auth('admin'), async (req, res) => {
  if (!VAPID_PUBLIC || !VAPID_PRIVATE) return res.status(400).json({ error: 'VAPID not configured' })
  const { title, body } = req.body
  const subs = pushDb.get('subscriptions').value()
  let sent = 0
  await Promise.all(subs.map(async s => {
    try { await webpush.sendNotification(s, JSON.stringify({ title: title || 'Alert', body: body || '' })); sent++ } catch (e) { console.error('Push Error:', e.message) }
  }))
  res.json({ sent })
})

app.get('/api/public/config', (req, res) => {
  res.json({ mapboxToken: MAPBOX_TOKEN, vapidPublicKey: VAPID_PUBLIC })
})

const tileCache = new Map()
const BLANK_PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+lmZkAAAAASUVORK5CYII=', 'base64')
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

// Dev-only admin ensure/reset
app.post('/api/public/ensure_admin', (req, res) => {
  const isProd = String(process.env.NODE_ENV || '').toLowerCase() === 'production'
  if (isProd) return res.status(403).json({ error: 'Disabled in production' })
  const email = (process.env.ADMIN_EMAIL || 'admin@local.test').trim().toLowerCase()
  const pass = String(process.env.ADMIN_PASSWORD || 'admin123')
  const existing = usersDb.get('users').find(u => String(u.email||'').trim().toLowerCase() === email).value()
  if (!existing) {
    const admin = { id: nanoid(), name: 'Administrator', email, pass: bcrypt.hashSync(pass, 10), role: 'admin', createdAt: new Date().toISOString() }
    usersDb.get('users').push(admin).write()
    return res.json({ created: true })
  }
  usersDb.get('users').find({ id: existing.id }).assign({ pass: bcrypt.hashSync(pass, 10), role: 'admin' }).write()
  res.json({ updated: true })
})

app.post('/api/public/normalize_users', (req, res) => {
  const isProd = String(process.env.NODE_ENV || '').toLowerCase() === 'production'
  if (isProd) return res.status(403).json({ error: 'Disabled in production' })
  const all = usersDb.get('users').value()
  const normalized = all.map(u => ({ ...u, email: String(u.email||'').trim().toLowerCase() }))
  usersDb.set('users', normalized).write()
  res.json({ normalized: normalized.length })
})

// Public data and exports
function catchesToGeoJSON(catches) {
  return {
    type: 'FeatureCollection',
    features: (catches || []).flatMap(c => {
      const lat = Number(c.lat)
      const lng = Number(c.lng)
      if (!Number.isFinite(lat) || !Number.isFinite(lng)) return []
      return [{
        type: 'Feature',
        geometry: { type: 'Point', coordinates: [lng, lat] },
        properties: { userId: c.userId, species: c.species, netType: c.netType || null, weightKg: c.weightKg, gear: c.gear, vessel: c.vessel, capturedAt: c.capturedAt }
      }]
    })
  }
}
function catchesToCSV(catches) {
  const header = 'species,netType,weightKg,gear,vessel,lat,lng,capturedAt\n'
  const rows = catches.map(c => [c.species, c.netType || '', c.weightKg || '', c.gear || '', c.vessel || '', c.lat, c.lng, c.capturedAt].join(',')).join('\n')
  return header + rows
}
app.get('/api/public/catches.geojson', (req, res) => {
  const { species, gear, from, to, userId } = req.query
  let list = catchesDb.get('catches').value()
  if (userId) list = list.filter(c => c.userId === userId)
  if (species) list = list.filter(c => c.species === species)
  if (gear) list = list.filter(c => (c.gear||'') === gear)
  if (from) list = list.filter(c => new Date(c.capturedAt) >= new Date(from))
  if (to) list = list.filter(c => new Date(c.capturedAt) <= new Date(to))
  res.json(catchesToGeoJSON(list))
})
app.get('/api/public/tracks.geojson', (req, res) => {
  const { from, to, userId, latest } = req.query
  let list = tracksDb.get('tracks').value()
  if (userId) list = list.filter(t => t.userId === userId)
  if (from) list = list.filter(t => new Date(t.recordedAt) >= new Date(from))
  if (to) list = list.filter(t => new Date(t.recordedAt) <= new Date(to))
  if (latest) {
    const byUser = new Map()
    list.forEach(t => {
      const uid = t.userId || 'unknown'
      const prev = byUser.get(uid)
      if (!prev) return void byUser.set(uid, t)
      const prevAt = new Date(prev.recordedAt || 0).getTime()
      const curAt = new Date(t.recordedAt || 0).getTime()
      if (curAt >= prevAt) byUser.set(uid, t)
    })
    list = Array.from(byUser.values())
  }
  const geo = { type: 'FeatureCollection', features: list.map(t => ({ type: 'Feature', geometry: { type: 'Point', coordinates: [t.lng, t.lat] }, properties: { userId: t.userId, recordedAt: t.recordedAt, speed: t.speed, heading: t.heading, accuracy: t.accuracy } })) }
  res.json(geo)
})
app.get('/api/public/catches.csv', (req, res) => {
  const { species, gear, from, to, userId } = req.query
  let list = catchesDb.get('catches').value()
  if (userId) list = list.filter(c => c.userId === userId)
  if (species) list = list.filter(c => c.species === species)
  if (gear) list = list.filter(c => (c.gear||'') === gear)
  if (from) list = list.filter(c => new Date(c.capturedAt) >= new Date(from))
  if (to) list = list.filter(c => new Date(c.capturedAt) <= new Date(to))
  res.setHeader('Content-Type','text/csv'); res.send(catchesToCSV(list))
})

app.use(express.static(path.join(__dirname, 'public')))
app.use('/uploads', express.static(UPLOAD_DIR))

const sseClients = []
app.get('/api/admin/live', auth(['admin','inspector']), (req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Connection': 'keep-alive' })
  res.write('\n')
  sseClients.push(res)
  
  // Send a heartbeat every 30s to keep connection alive
  const hb = setInterval(() => res.write(':\n\n'), 30000)
  
  req.on('close', () => {
    clearInterval(hb)
    const i = sseClients.indexOf(res)
    if (i >= 0) sseClients.splice(i,1)
  })
})
function broadcastTrack(point) {
  const data = `data: ${JSON.stringify(point)}\n\n`
  sseClients.forEach(res => { try { res.write(data) } catch (e) { console.error('SSE Write Error (Track):', e.message) } })
}
function broadcastStatus(payload) {
  const data = `data: ${JSON.stringify(payload)}\n\n`
  sseClients.forEach(res => { try { res.write(data) } catch (e) { console.error('SSE Write Error (Status):', e.message) } })
}
function broadcastCatch(item) {
  const u = usersDb.get('users').find({ id: item.userId }).value()
  const payload = { type: 'catch', item: { ...item, user: u ? { id: u.id, name: u.name, email: u.email } : null } }
  const data = `data: ${JSON.stringify(payload)}\n\n`
  sseClients.forEach(res => { try { res.write(data) } catch (e) { console.error('SSE Write Error (Catch):', e.message) } })
}
function broadcastAlert(a) {
  const u = usersDb.get('users').find({ id: a.userId }).value()
  const payload = { type: 'alert', item: { ...a, user: u ? { id: u.id, name: u.name, email: u.email } : null } }
  const data = `data: ${JSON.stringify(payload)}\n\n`
  sseClients.forEach(res => { try { res.write(data) } catch (e) { console.error('SSE Write Error (Alert):', e.message) } })
}

app.get('/', (req, res) => {
  res.redirect('/user')
})
app.get('/user', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'user.html'))
})

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'))
})

const http = require('http')
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
if (IS_SERVERLESS) {
  module.exports = app
} else {
  startServer(BASE_PORT)
}
app.get('/api/public/hostinfo', (req, res) => {
  const ips = getLANIPs()
  res.json({ port: CURRENT_PORT, ips, urls: ips.map(ip => `http://${ip}:${CURRENT_PORT}/`) })
})
app.post('/api/activity_logs', auth(), (req, res) => {
  const { type, category, lat, lng, line, details } = req.body
  if (!type || lat == null || lng == null) return res.status(400).json({ error: 'Missing fields' })
  const ACTIVITY_CATEGORIES = {
    catching_fish: 'fishing',
    unloading_catch: 'fishing',
    boat_launching_docking: 'fishing',
    mangrove_planting: 'environmental',
    coastal_cleanup: 'environmental',
    monitoring_water_quality: 'environmental',
    checking_coral_reef: 'environmental',
    swimming_snorkeling: 'tourism',
    scuba_diving: 'tourism',
    boating_kayaking: 'tourism',
    beach_events: 'tourism',
    cargo_unloading: 'maritime',
    movement_of_fishing_vessels: 'maritime',
    transporting_goods_small_boats: 'maritime',
    illegal_fishing: 'illegal',
    unauthorized_structures: 'illegal',
    illegal_dumping: 'illegal',
    patrol: 'maritime'
  }
  const valid = Object.keys(ACTIVITY_CATEGORIES)
  const t = String(type)
  if (!valid.includes(t)) return res.status(400).json({ error: 'Invalid type' })
  const cat = ACTIVITY_CATEGORIES[t] || (category || null)
  const log = { id: nanoid(), user_id: req.user.id, type: t, category: cat, location: { lat: parseFloat(lat), lng: parseFloat(lng) }, geom_line: Array.isArray(line) ? line : null, details: details || null, created_at: new Date().toISOString() }
  activityDb.get('activity_logs').push(log).write()
  res.json(log)
})
app.post('/api/activity_logs/upload', auth(), upload.single('photo'), async (req, res) => {
  try {
    let { type, category, lat, lng, line, details, note } = req.body
    if (!type) return res.status(400).json({ error: 'Missing activity type' })
    const ACTIVITY_CATEGORIES = {
      catching_fish: 'fishing',
      unloading_catch: 'fishing',
      boat_launching_docking: 'fishing',
      mangrove_planting: 'environmental',
      coastal_cleanup: 'environmental',
      monitoring_water_quality: 'environmental',
      checking_coral_reef: 'environmental',
      swimming_snorkeling: 'tourism',
      scuba_diving: 'tourism',
      boating_kayaking: 'tourism',
      beach_events: 'tourism',
      cargo_unloading: 'maritime',
      movement_of_fishing_vessels: 'maritime',
      transporting_goods_small_boats: 'maritime',
      illegal_fishing: 'illegal',
      unauthorized_structures: 'illegal',
      illegal_dumping: 'illegal',
      patrol: 'maritime'
    }
    const t = String(type)
    const valid = Object.keys(ACTIVITY_CATEGORIES)
    if (!valid.includes(t)) return res.status(400).json({ error: 'Invalid type' })
    let latNum = lat != null ? parseFloat(lat) : null
    let lngNum = lng != null ? parseFloat(lng) : null
    if ((latNum == null || lngNum == null) && req.file) {
      const exifGps = await exifr.gps(req.file.path).catch(() => null)
      if (exifGps && exifGps.latitude && exifGps.longitude) { latNum = exifGps.latitude; lngNum = exifGps.longitude }
    }
    if (latNum == null || lngNum == null) return res.status(400).json({ error: 'Missing coordinates' })
    let lineArr = null
    if (Array.isArray(line)) { lineArr = line }
    else if (typeof line === 'string' && line) { try { const p = JSON.parse(line); if (Array.isArray(p)) lineArr = p } catch {} }
    const cat = ACTIVITY_CATEGORIES[t] || (category || null)
    const photoUrl = req.file ? `/uploads/${req.file.filename}` : null
    const detailsObj = details ? (typeof details === 'string' ? (() => { try { return JSON.parse(details) } catch { return { note: details } } })() : details) : (note ? { note } : null)
    const log = { id: nanoid(), user_id: req.user.id, type: t, category: cat, location: { lat: latNum, lng: lngNum }, geom_line: lineArr, details: detailsObj, photoUrl, created_at: new Date().toISOString() }
    activityDb.get('activity_logs').push(log).write()
    if (req.file) {
      const exifFull = await exifr.parse(req.file.path).catch(() => null)
      const img = { id: nanoid(), activity_id: log.id, bucket_key: photoUrl, exif: exifFull || null, created_at: new Date().toISOString() }
      imagesDb.get('images').push(img).write()
    }
    res.json(log)
  } catch (e) {
    res.status(500).json({ error: 'Upload failed' })
  }
})
app.get('/api/activity_logs/me', auth(), (req, res) => {
  const list = activityDb.get('activity_logs').filter(a => a.user_id === req.user.id).value()
  // Sort by created_at desc
  list.sort((a,b) => new Date(b.created_at) - new Date(a.created_at))
  res.json(list)
})
app.get('/api/activity_logs', auth(['admin','inspector']), (req, res) => {
  const { type, userId, from, to, format } = req.query
  let list = activityDb.get('activity_logs').value()
  if (type) list = list.filter(a => a.type === type)
  if (userId) list = list.filter(a => a.user_id === userId)
  if (from) list = list.filter(a => new Date(a.created_at) >= new Date(from))
  if (to) list = list.filter(a => new Date(a.created_at) <= new Date(to))
  if (format === 'geojson') {
    const features = []
    list.forEach(a => {
      features.push({ type: 'Feature', geometry: { type: 'Point', coordinates: [a.location.lng, a.location.lat] }, properties: { id: a.id, type: a.type, category: a.category || null, user_id: a.user_id, created_at: a.created_at } })
      if (Array.isArray(a.geom_line)) features.push({ type: 'Feature', geometry: { type: 'LineString', coordinates: a.geom_line.map(p => [p.lng, p.lat]) }, properties: { id: a.id, type: a.type, category: a.category || null, user_id: a.user_id, created_at: a.created_at } })
    })
    return res.json({ type: 'FeatureCollection', features })
  }
  res.json(list)
})
app.delete('/api/activity_logs/:id', auth(['admin','inspector']), (req, res) => {
  const id = req.params.id
  const exists = activityDb.get('activity_logs').find({ id }).value()
  if (!exists) return res.status(404).json({ error: 'Not found' })
  activityDb.set('activity_logs', activityDb.get('activity_logs').filter(a => a.id !== id).value()).write()
  res.json({ ok: true })
})
app.get('/api/admin/activity_insights', auth(['admin','inspector']), (req, res) => {
  const logs = activityDb.get('activity_logs').value()
  const zones = zonesDb.get('zones').value()
  const areas = protectedAreasDb.get('protected_areas').value()
  let illegalProtected = 0
  const illegalTypes = ['illegal_fishing','unauthorized_structures','illegal_dumping']
  logs.forEach(a => {
    if (illegalTypes.includes(a.type)) {
      const turf = require('@turf/turf')
      const pt = turf.point([a.location.lng, a.location.lat])
      const polys = [
        ...zones.map(z => z.geometry ? { type: 'Feature', geometry: z.geometry } : null).filter(Boolean),
        ...areas.map(ar => ar.geom ? { type: 'Feature', geometry: ar.geom } : null).filter(Boolean)
      ]
      if (polys.some(poly => { try { return turf.booleanPointInPolygon(pt, poly) } catch { return false } })) illegalProtected++
    }
  })
  const weekAgo = Date.now() - 7*24*60*60*1000
  const approaches = alertsDb.get('alerts').filter(a => a.type === 'approach' && new Date(a.recordedAt).getTime() >= weekAgo).value().length
  let patrolKm = 0
  logs.forEach(a => {
    if ((a.type === 'patrol' || a.type === 'movement_of_fishing_vessels') && Array.isArray(a.geom_line) && a.geom_line.length>1) {
      const line = { type: 'Feature', geometry: { type: 'LineString', coordinates: a.geom_line.map(p => [p.lng, p.lat]) } }
      try { const turf = require('@turf/turf'); patrolKm += turf.length(line, { units: 'kilometers' }) } catch {}
    }
  })
  res.json({ illegal_in_protected: illegalProtected, approaches_last7: approaches, patrol_km: Number(patrolKm.toFixed(2)) })
})
app.post('/api/images', auth(), (req, res) => {
  const { catch_id, bucket_key, exif } = req.body
  if (!catch_id || !bucket_key) return res.status(400).json({ error: 'Missing fields' })
  const img = { id: nanoid(), catch_id, bucket_key, exif: exif || null, created_at: new Date().toISOString() }
  imagesDb.get('images').push(img).write(); res.json(img)
})
app.get('/api/images', auth(), (req, res) => {
  const { catch_id } = req.query
  let list = imagesDb.get('images').value()
  if (catch_id) list = list.filter(i => i.catch_id === catch_id)
  res.json(list)
})
app.get('/api/admin/protected_areas', auth('admin'), (req, res) => {
  res.json(protectedAreasDb.get('protected_areas').value())
})
app.post('/api/admin/protected_areas', auth('admin'), (req, res) => {
  const { name, geom, rules } = req.body
  if (!name || !geom) return res.status(400).json({ error: 'Missing fields' })
  const pa = { id: nanoid(), name, geom, rules: rules || null, created_at: new Date().toISOString() }
  protectedAreasDb.get('protected_areas').push(pa).write(); res.json(pa)
})
app.patch('/api/admin/protected_areas/:id', auth('admin'), (req, res) => {
  const id = req.params.id
  const { name, geom, rules } = req.body
  const pa = protectedAreasDb.get('protected_areas').find({ id }).value()
  if (!pa) return res.status(404).json({ error: 'Not found' })
  if (geom) {
    const ok = geom && geom.type === 'Polygon' && Array.isArray(geom.coordinates) && Array.isArray(geom.coordinates[0]) && geom.coordinates[0].length >= 4
    if (!ok) return res.status(400).json({ error: 'Invalid polygon' })
  }
  const next = { name: name || pa.name, geom: geom || pa.geom, rules: rules !== undefined ? rules : pa.rules }
  protectedAreasDb.get('protected_areas').find({ id }).assign(next).write()
  res.json({ ok: true })
})
app.delete('/api/admin/protected_areas/:id', auth('admin'), (req, res) => {
  const id = req.params.id
  protectedAreasDb.set('protected_areas', protectedAreasDb.get('protected_areas').filter(p => p.id !== id).value()).write(); res.json({ ok: true })
})

app.use((err, req, res, next) => {
  try { console.error('handler_error', err) } catch {}
  if (!res.headersSent) res.status(500).json({ error: 'Internal error' })
})

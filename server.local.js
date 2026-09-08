const express = require('express')
const cors = require('cors')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const low = require('lowdb')
const FileSync = require('lowdb/adapters/FileSync')
const Memory = require('lowdb/adapters/Memory')
const { nanoid } = require('nanoid')
const path = require('path')
const fs = require('fs')
const https = require('https')
const multer = require('multer')
const exifr = require('exifr')
const nodemailer = require('nodemailer')
const webpush = require('web-push')
const os = require('os')
const crypto = require('crypto')

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
const _googleStates = new Map() // state -> { createdAt }
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
const ROLE_PRIORITY = { admin: 3, researcher: 2, inspector: 1, fisher: 0 }
function findUserByEmail(list, email) {
  const emailKey = String(email || '').trim().toLowerCase()
  if (!emailKey) return null
  const matches = (list || []).filter(u => String(u.email || '').trim().toLowerCase() === emailKey)
  if (matches.length === 0) return null
  if (matches.length === 1) return matches[0]
  matches.sort((a, b) => (ROLE_PRIORITY[b.role || 'fisher'] || 0) - (ROLE_PRIORITY[a.role || 'fisher'] || 0))
  return matches[0]
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
  // 1) Prefer id_token when available (fast, signed)
  if (codeTokens && codeTokens.id_token) {
    try {
      const ticket = await client.verifyIdToken({ idToken: codeTokens.id_token, audience: GOOGLE_CLIENT_ID })
      const payload = ticket.getPayload()
      const clean = sanitizeGoogleProfile(payload)
      if (clean) return clean
    } catch (e) {}
  }
  // 2) Fallback: exchange access_token for userinfo via Google userinfo endpoint
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
function upsertGoogleUserLocal({ sub, email, name, picture }) {
  const emailKey = String(email || '').trim().toLowerCase()
  const subKey = String(sub || '').trim()
  if (!emailKey || !subKey) throw new Error('Missing Google profile')
  const list = usersDb.get('users').value() || []
  let user = list.find(u => u.googleId && String(u.googleId) === subKey)
  const roleSafe = 'fisher'
  const now = new Date().toISOString()
  if (!user) user = findUserByEmail(list, emailKey)
  if (user) {
    const patch = { googleId: subKey }
    if (picture) patch.avatarUrl = String(picture)
    if (!user.name) patch.name = name
    if (!user.email) patch.email = emailKey
    usersDb.get('users').find({ id: user.id }).assign(patch).write()
    user = usersDb.get('users').find({ id: user.id }).value()
  } else {
    user = {
      id: nanoid(),
      name: name || emailKey.split('@')[0] || 'Google User',
      email: emailKey,
      role: roleSafe,
      pass: null,
      googleId: subKey,
      avatarUrl: picture || null,
      createdAt: now
    }
    usersDb.get('users').push(user).write()
  }
  return user
}

const app = express()
app.use(cors())
app.use(express.json({ limit: '2mb' }))
app.use(express.urlencoded({ extended: true }))

process.on('unhandledRejection', (e) => { try { console.error('unhandledRejection', e) } catch {} })
process.on('uncaughtException', (e) => { try { console.error('uncaughtException', e) } catch {} })

const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me'

const IS_SERVERLESS = !!process.env.VERCEL || !!process.env.NOW_REGION
const DATA_DIR = process.env.DATA_DIR || (IS_SERVERLESS ? path.join('/tmp', 'data') : path.join(__dirname, 'data'))
const UPLOAD_DIR = process.env.UPLOAD_DIR || (IS_SERVERLESS ? path.join('/tmp', 'uploads') : path.join(__dirname, 'uploads'))

const defaultCollections = {
  'users.json': { users: [] },
  'catches.json': [],
  'tracks.json': [],
  'species.json': [],
  'zones.json': [],
  'alerts.json': [],
  'push.json': { subscriptions: [] },
  'activity_logs.json': [],
  'images.json': [],
  'protected_areas.json': [],
  'status_events.json': [],
  'vessels.json': []
}

let USE_MEMORY_FALLBACK = false
try {
  fs.mkdirSync(DATA_DIR, { recursive: true })
  fs.mkdirSync(UPLOAD_DIR, { recursive: true })
  Object.entries(defaultCollections).forEach(([fileName, defaultContent]) => {
    const fullPath = path.join(DATA_DIR, fileName)
    try {
      if (!fs.existsSync(fullPath)) {
        fs.writeFileSync(fullPath, JSON.stringify(defaultContent, null, 2))
      } else {
        try {
          const raw = fs.readFileSync(fullPath, 'utf8').trim()
          if (!raw) {
            fs.writeFileSync(fullPath, JSON.stringify(defaultContent, null, 2))
          } else {
            JSON.parse(raw)
          }
        } catch {
          fs.writeFileSync(fullPath, JSON.stringify(defaultContent, null, 2))
        }
      }
    } catch (e) { throw e }
  })
} catch (e) {
  USE_MEMORY_FALLBACK = true
  console.warn(`[db] Disk storage unavailable (DATA_DIR="${DATA_DIR}" error: ${e && e.code || e && e.message || String(e)}). Falling back to in-memory LowDB. Data written during this instance will NOT persist between function cold-starts.`)
}

function mkAdapter(fileName, defaultContent) {
  if (USE_MEMORY_FALLBACK) return new Memory(fileName)
  try { return new FileSync(path.join(DATA_DIR, fileName)) } catch (e) {
    console.warn(`[db] FileSync adapter failed for ${fileName}: ${e && e.message || e}. Falling back to Memory adapter.`)
    return new Memory(fileName)
  }
}

const usersAdapter = mkAdapter('users.json')
const catchesAdapter = mkAdapter('catches.json')
const tracksAdapter = mkAdapter('tracks.json')
const speciesAdapter = mkAdapter('species.json')
const zonesAdapter = mkAdapter('zones.json')
const alertsAdapter = mkAdapter('alerts.json')
const pushAdapter = mkAdapter('push.json')
const activityAdapter = mkAdapter('activity_logs.json')
const imagesAdapter = mkAdapter('images.json')
const protectedAreasAdapter = mkAdapter('protected_areas.json')
const statusAdapter = mkAdapter('status_events.json')
const vesselsAdapter = mkAdapter('vessels.json')

let usersDb = low(usersAdapter)
let catchesDb = low(catchesAdapter)
let tracksDb = low(tracksAdapter)
let speciesDb = low(speciesAdapter)
let zonesDb = low(zonesAdapter)
let alertsDb = low(alertsAdapter)
let pushDb = low(pushAdapter)
let activityDb = low(activityAdapter)
let imagesDb = low(imagesAdapter)
let protectedAreasDb = low(protectedAreasAdapter)
let statusDb = low(statusAdapter)
let vesselsDb = low(vesselsAdapter)

if (USE_MEMORY_FALLBACK) {
  const defaults = {
    users: [], catches: [], tracks: [], species: [], zones: [], alerts: [],
    push: { subscriptions: [] }, activity_logs: [], images: [], protected_areas: [], status_events: [], vessels: []
  }
  usersDb.defaults({ users: defaults.users }).write()
  catchesDb.defaults(defaults.catches).write()
  tracksDb.defaults(defaults.tracks).write()
  speciesDb.defaults(defaults.species).write()
  zonesDb.defaults(defaults.zones).write()
  alertsDb.defaults(defaults.alerts).write()
  pushDb.defaults(defaults.push).write()
  activityDb.defaults(defaults.activity_logs).write()
  imagesDb.defaults(defaults.images).write()
  protectedAreasDb.defaults(defaults.protected_areas).write()
  statusDb.defaults(defaults.status_events).write()
  vesselsDb.defaults(defaults.vessels).write()
  // Also seed a single default admin user so login works immediately after cold start (no file DB needed)
  try {
    const bcrypt = require('bcryptjs')
    const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@local.test'
    const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123'
    const existingAdmin = usersDb.get('users').find({ role: 'admin' }).value()
    if (!existingAdmin) {
      try {
        const hash = bcrypt.hashSync(ADMIN_PASSWORD, 10)
        usersDb.get('users').push({ id: nanoid(), email: ADMIN_EMAIL, passwordHash: hash, role: 'admin', name: 'Admin', createdAt: new Date().toISOString() }).write()
        console.log('[db] Memory mode: seeded default admin user (' + ADMIN_EMAIL + ').')
      } catch (e) { console.warn('[db] Memory mode: seed admin failed:', e && e.message || e) }
    }
  } catch {}
}

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
vesselsDb.defaults({ vessels: [] }).write()

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

function normalizeText(value) {
  const out = value == null ? '' : String(value).trim()
  return out
}

function normalizeVesselRecord(record) {
  const engine = normalizeText(record.engine || record.engine_gear)
  return {
    id: String(record.id),
    vessel_registration_number: normalizeText(record.vessel_registration_number),
    vessel_name: normalizeText(record.vessel_name),
    owner_name: normalizeText(record.owner_name),
    barangay: normalizeText(record.barangay),
    engine,
    engine_gear: engine,
    userId: record.userId != null ? String(record.userId) : null,
    createdAt: record.createdAt || record.created_at || new Date().toISOString(),
    updatedAt: record.updatedAt || record.updated_at || new Date().toISOString()
  }
}

function getAllVesselsLocal() {
  return (vesselsDb.get('vessels').value() || [])
    .map(normalizeVesselRecord)
    .sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0))
}

function findVesselByIdLocal(id) {
  if (!id) return null
  return getAllVesselsLocal().find(v => v.id === String(id)) || null
}

function findVesselByRegistrationLocal(registrationNumber, excludeId) {
  const target = normalizeText(registrationNumber).toLowerCase()
  if (!target) return null
  return getAllVesselsLocal().find(v => v.id !== excludeId && v.vessel_registration_number.toLowerCase() === target) || null
}

function seedLocalVesselsFromLegacyData() {
  const existing = getAllVesselsLocal()
  const byRegistration = new Set(existing.map(v => v.vessel_registration_number.toLowerCase()).filter(Boolean))
  const additions = []

  const users = usersDb.get('users').value() || []
  users.forEach(u => {
    const reg = normalizeText(u.vessel_registration_number || u.fisher_id)
    const name = normalizeText(u.vessel_name)
    const owner = normalizeText(u.name)
    if (!reg || !name || !owner || byRegistration.has(reg.toLowerCase())) return
    byRegistration.add(reg.toLowerCase())
    additions.push({
      id: nanoid(),
      vessel_registration_number: reg,
      vessel_name: name,
      owner_name: owner,
      userId: u.id,
      createdAt: u.createdAt || new Date().toISOString(),
      updatedAt: new Date().toISOString()
    })
  })

  const catches = catchesDb.get('catches').value() || []
  catches.forEach(c => {
    const reg = normalizeText(c.vesselRegistrationNumber)
    const name = normalizeText(c.vesselName || c.vessel)
    const owner = normalizeText(c.ownerName)
    if (!reg || !name || !owner || byRegistration.has(reg.toLowerCase())) return
    byRegistration.add(reg.toLowerCase())
    additions.push({
      id: nanoid(),
      vessel_registration_number: reg,
      vessel_name: name,
      owner_name: owner,
      userId: c.userId || null,
      createdAt: c.createdAt || new Date().toISOString(),
      updatedAt: new Date().toISOString()
    })
  })

  if (additions.length) {
    vesselsDb.get('vessels').push(...additions).write()
  }
}

function resolveCatchVesselLocal(body) {
  const vesselId = normalizeText(body.vesselId)
  if (vesselId) {
    const vessel = findVesselByIdLocal(vesselId)
    if (!vessel) {
      const err = new Error('Selected vessel not found')
      err.statusCode = 400
      throw err
    }
    return {
      vesselId: vessel.id,
      vessel: vessel.vessel_name,
      vesselRegistrationNumber: vessel.vessel_registration_number,
      vesselName: vessel.vessel_name,
      ownerName: vessel.owner_name,
      barangay: vessel.barangay,
      engine: vessel.engine || vessel.engine_gear || null
    }
  }

  return {
    vesselId: null,
    vessel: normalizeText(body.vessel || body.vesselName) || null,
    vesselRegistrationNumber: normalizeText(body.vesselRegistrationNumber) || null,
    vesselName: normalizeText(body.vesselName || body.vessel) || null,
    ownerName: normalizeText(body.ownerName) || null,
    barangay: normalizeText(body.barangay) || null,
    engine: normalizeText(body.engine || body.gear) || null
  }
}

function enrichCatchWithVesselLocal(catchItem) {
  let vessel = catchItem && catchItem.vesselId ? findVesselByIdLocal(catchItem.vesselId) : null
  if (!vessel && catchItem && catchItem.vesselRegistrationNumber) {
    vessel = findVesselByRegistrationLocal(catchItem.vesselRegistrationNumber)
  }
  return {
    ...catchItem,
    vesselId: catchItem.vesselId || (vessel ? vessel.id : null),
    vesselRegistrationNumber: catchItem.vesselRegistrationNumber || (vessel ? vessel.vessel_registration_number : null),
    vesselName: catchItem.vesselName || catchItem.vessel || (vessel ? vessel.vessel_name : null),
    ownerName: catchItem.ownerName || (vessel ? vessel.owner_name : null),
    barangay: catchItem.barangay || (vessel ? vessel.barangay : null),
    engine: (vessel && (vessel.engine || vessel.engine_gear)) || catchItem.engine || catchItem.gear || null
  }
}

function backfillEngineFromCatchesToVesselsLocal() {
  const vessels = vesselsDb.get('vessels').value() || []
  const catches = catchesDb.get('catches').value() || []
  const changes = []
  vessels.forEach(v => {
    if (normalizeText(v.engine || v.engine_gear)) return
    const linked = catches.find(c =>
      String(c.vesselId || '') === String(v.id) ||
      normalizeText(c.vesselRegistrationNumber || c.vessel_registration_number) === normalizeText(v.vessel_registration_number)
    )
    if (linked && normalizeText(linked.engine || linked.gear)) {
      const e = normalizeText(linked.engine || linked.gear)
      v.engine = e
      v.engine_gear = e
      changes.push(v)
    }
  })
  if (changes.length) {
    vesselsDb.write()
  }
}

seedLocalVesselsFromLegacyData()
backfillEngineFromCatchesToVesselsLocal()

try {
  const admin = usersDb.get('users').find(u => u.role === 'admin').value()
  const unassignedVessels = vesselsDb.get('vessels').filter(v => !v.userId).value()
  if (admin && unassignedVessels.length > 0) {
    vesselsDb.get('vessels').filter(v => !v.userId).assign({ userId: admin.id }).write()
  }
} catch {}

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

function isAdmin(u) { return u && u.role === 'admin' }
function isSelfOrAdmin(req, ownerId) {
  if (isAdmin(req.user)) return true
  return String(ownerId || '') === String(req.user.id || '')
}
function scopeByUser(req, list, ownerKey = 'userId') {
  if (isAdmin(req.user)) return list || []
  const selfId = String(req.user.id || '')
  const key = ownerKey
  return (list || []).filter(item => {
    const owner = item && item[key] != null ? item[key] : (item && item.user_id != null ? item.user_id : null)
    return String(owner || '') === selfId
  })
}

app.post('/api/auth/register', async (req, res) => {
  let { name, email, password, role } = req.body
  if (!name || !email || !password) return res.status(400).json({ error: 'Missing fields' })
  email = String(email).trim().toLowerCase()
  const exists = findUserByEmail(usersDb.get('users').value() || [], email)
  if (exists) return res.status(409).json({ error: 'Email already registered' })
  const hash = bcrypt.hashSync(password, 10)
  const roleSafe = ['admin','inspector','fisher','researcher'].includes((role||'').toLowerCase()) ? role.toLowerCase() : 'fisher'
  const user = { id: nanoid(), name, email, pass: hash, role: roleSafe, createdAt: new Date().toISOString() }
  usersDb.get('users').push(user).write()
  const token = createToken(user)
  res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } })
})

app.post('/api/auth/login', async (req, res) => {
  let { email, password } = req.body
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' })
  email = String(email).trim().toLowerCase()
  const list = usersDb.get('users').value()
  const user = findUserByEmail(list, email)
  if (!user) return res.status(401).json({ error: 'Invalid credentials' })
  const ok = user.pass ? bcrypt.compareSync(password, user.pass) : false
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' })
  const token = createToken(user)
  res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role, barangay: user.barangay || null, vessel_name: user.vessel_name || null, fisher_id: user.fisher_id || null } })
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
    const user = upsertGoogleUserLocal(profile)
    const jwtToken = createToken(user)
    const safeUser = { id: user.id, name: user.name, email: user.email, role: user.role, barangay: user.barangay || null, vessel_name: user.vessel_name || null, fisher_id: user.fisher_id || null, avatarUrl: user.avatarUrl || profile.picture || null }
    // Set lightweight session cookie and redirect with token via query (handled by login page JS)
    const redirectBase = (safeUser.role === 'admin') ? '/admin.html' : '/user.html'
    const sep = redirectBase.includes('?') ? '&' : '?'
    const dest = `${redirectBase}${sep}token=${encodeURIComponent(jwtToken)}&user=${encodeURIComponent(JSON.stringify(safeUser))}`
    return res.redirect(dest)
  } catch (e) {
    console.error('[Google OAuth] Callback error:', e && e.message)
    const msg = e && e.message ? String(e.message) : 'Google sign-in failed'
    return res.redirect('/login.html?error=' + encodeURIComponent(msg))
  }
})

// --- DASHBOARD STATS (Local Mode) ---
app.get('/api/dashboard/stats', auth(), async (req, res) => {
  try {
    const now = new Date()
    const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate())
    const startOfWeek = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000)
    const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1)

    // 1. Total catch today (kg) for current user
    const catchesToday = catchesDb.get('catches').filter(c => c.userId === req.user.id && new Date(c.capturedAt || c.createdAt) >= startOfToday).value() || []
    const totalWeightToday = catchesToday.reduce((sum, c) => sum + (Number(c.weightKg) || 0), 0)

    // 2. Active vessels for current user
    let activeVessels = 0
    const myTracking = trackingStateByUserId.get(req.user.id)
    if (myTracking && myTracking.active) activeVessels = 1

    // 3. Total coastal activities this week for current user
    const activitiesWeek = activityDb.get('activity_logs').filter(a => a.user_id === req.user.id && new Date(a.created_at) >= startOfWeek).value() || []

    // 4. Top 3 species this month (current user)
    const monthlyCatches = catchesDb.get('catches').filter(c => c.userId === req.user.id && new Date(c.capturedAt || c.createdAt) >= startOfMonth).value() || []
    const speciesCounts = monthlyCatches.reduce((acc, c) => {
      const s = c.species || 'Unknown'
      acc[s] = (acc[s] || 0) + 1
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
      const mStart = new Date(d.getFullYear(), d.getMonth(), 1)
      const mEnd = new Date(d.getFullYear(), d.getMonth() + 1, 0, 23, 59, 59)
      const mData = catchesDb.get('catches').filter(c => {
        const cat = new Date(c.capturedAt || c.createdAt)
        return c.userId === req.user.id && cat >= mStart && cat <= mEnd
      }).value() || []
      const bySpecies = {}
      mData.forEach(c => {
        const s = c.species || 'Unknown'
        bySpecies[s] = (bySpecies[s] || 0) + (Number(c.weightKg) || 0)
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
      activitiesWeek: activitiesWeek.length,
      topSpecies,
      trend: { months, series }
    })
  } catch (e) {
    res.status(500).json({ error: e.message })
  }
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
  const exists = findUserByEmail(usersDb.get('users').value() || [], email)
  if (exists) return res.status(409).json({ error: 'Email exists' })
  const hash = bcrypt.hashSync(password, 10)
  const user = { id: nanoid(), name, email, pass: hash, role: 'admin', createdAt: new Date().toISOString() }
  usersDb.get('users').push(user).write()
  res.json({ ok: true, user: { id: user.id, name: user.name, email: user.email, role: user.role } })
})

app.get('/api/vessels', auth(), async (req, res) => {
  const userId = req.query && req.query.userId != null ? String(req.query.userId) : null
  let list = getAllVesselsLocal()
  if (!isAdmin(req.user)) {
    const selfId = String(req.user.id || '')
    if (userId && userId !== selfId) return res.status(403).json({ error: 'Forbidden' })
    list = list.filter(v => String(v.userId || '') === selfId)
  } else if (userId) {
    list = list.filter(v => String(v.userId || '') === userId)
  }
  res.json(list)
})

app.get('/api/vessels/:id', auth(), async (req, res) => {
  const vessel = findVesselByIdLocal(req.params.id)
  if (!vessel) return res.status(404).json({ error: 'Vessel not found' })
  if (!isSelfOrAdmin(req, vessel.userId)) return res.status(403).json({ error: 'Forbidden' })
  res.json(vessel)
})

app.post('/api/vessels', auth(), async (req, res) => {
  const vessel_registration_number = normalizeText(req.body.vessel_registration_number)
  const vessel_name = normalizeText(req.body.vessel_name)
  const owner_name = normalizeText(req.body.owner_name)
  const barangay = normalizeText(req.body.barangay)
  const engine = normalizeText(req.body.engine || req.body.engine_gear)
  if (!vessel_registration_number || !vessel_name || !owner_name || !barangay) {
    return res.status(400).json({ error: 'Registration #, Name, Owner, and Barangay are required' })
  }
  if (findVesselByRegistrationLocal(vessel_registration_number)) {
    return res.status(409).json({ error: 'Vessel registration number already exists' })
  }
  const vessel = {
    id: nanoid(),
    vessel_registration_number,
    vessel_name,
    owner_name,
    barangay,
    engine,
    engine_gear: engine,
    userId: req.user.id,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  }
  vesselsDb.get('vessels').push(vessel).write()
  res.json(normalizeVesselRecord(vessel))
})

app.patch('/api/vessels/:id', auth(), async (req, res) => {
  const id = String(req.params.id)
  const existing = findVesselByIdLocal(id)
  if (!existing) return res.status(404).json({ error: 'Vessel not found' })
  if (!isSelfOrAdmin(req, existing.userId)) return res.status(403).json({ error: 'Forbidden' })

  const vessel_registration_number = normalizeText(req.body.vessel_registration_number)
  const vessel_name = normalizeText(req.body.vessel_name)
  const owner_name = normalizeText(req.body.owner_name)
  const barangay = normalizeText(req.body.barangay)
  const engine = normalizeText(req.body.engine || req.body.engine_gear)
  if (!vessel_registration_number || !vessel_name || !owner_name || !barangay) {
    return res.status(400).json({ error: 'Registration #, Name, Owner, and Barangay are required' })
  }
  if (findVesselByRegistrationLocal(vessel_registration_number, id)) {
    return res.status(409).json({ error: 'Vessel registration number already exists' })
  }

  const updatedAt = new Date().toISOString()
  vesselsDb.get('vessels').find({ id }).assign({
    vessel_registration_number,
    vessel_name,
    owner_name,
    barangay,
    engine,
    engine_gear: engine,
    updatedAt
  }).write()

  ;(catchesDb.get('catches').value() || []).forEach(c => {
    if (String(c.vesselId || '') !== id) return
    if (!isAdmin(req.user) && !isSelfOrAdmin(req, c.userId)) return
    catchesDb.get('catches').find({ id: c.id }).assign({
      vessel: vessel_name,
      vesselRegistrationNumber: vessel_registration_number,
      vesselName: vessel_name,
      ownerName: owner_name
    }).write()
  })

  res.json(normalizeVesselRecord({ ...existing, vessel_registration_number, vessel_name, owner_name, barangay, updatedAt }))
})

app.delete('/api/vessels/:id', auth('admin'), async (req, res) => {
  const id = String(req.params.id)
  const existing = findVesselByIdLocal(id)
  if (!existing) return res.status(404).json({ error: 'Vessel not found' })
  vesselsDb.set('vessels', vesselsDb.get('vessels').filter(v => String(v.id) !== id).value()).write()
  ;(catchesDb.get('catches').value() || []).forEach(c => {
    if (String(c.vesselId || '') !== id) return
    catchesDb.get('catches').find({ id: c.id }).assign({ vesselId: null }).write()
  })
  res.json({ ok: true })
})

app.post('/api/catches', auth(), async (req, res) => {
  const { species, netType, weightKg, lengthCm, gear, photoUrl, note, lat, lng, capturedAt, hoursFished, numHooksPanels, numHauls } = req.body
  if (lat == null || lng == null) return res.status(400).json({ error: 'Missing coordinates' })
  let vesselInfo
  try {
    vesselInfo = resolveCatchVesselLocal(req.body)
  } catch (e) {
    return res.status(e.statusCode || 400).json({ error: e.message })
  }
  const catchItem = {
    id: nanoid(),
    userId: req.user.id,
    species: species || 'unknown',
    netType: netType || null,
    weightKg: weightKg || null,
    lengthCm: lengthCm || null,
    gear: gear || null,
    hoursFished: hoursFished != null ? (isFinite(parseFloat(hoursFished)) ? parseFloat(hoursFished) : null) : null,
    numHooksPanels: numHooksPanels != null ? (isFinite(parseInt(numHooksPanels)) ? parseInt(numHooksPanels) : null) : null,
    numHauls: numHauls != null ? (isFinite(parseInt(numHauls)) ? parseInt(numHauls) : null) : null,
    vesselId: vesselInfo.vesselId,
    vessel: vesselInfo.vessel,
    vesselRegistrationNumber: vesselInfo.vesselRegistrationNumber,
    vesselName: vesselInfo.vesselName,
    ownerName: vesselInfo.ownerName,
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
  res.json(enrichCatchWithVesselLocal(catchItem))
})

// Photo upload with EXIF GPS fallback
const upload = multer({ dest: UPLOAD_DIR })
app.post('/api/catches/upload', auth(), upload.single('photo'), async (req, res) => {
  try {
    const { species, netType, weightKg, lengthCm, gear, note, lat, lng, capturedAt, hoursFished, numHooksPanels, numHauls } = req.body
    let latNum = lat != null ? parseFloat(lat) : null
    let lngNum = lng != null ? parseFloat(lng) : null
    if ((latNum == null || lngNum == null) && req.file) {
      const exif = await exifr.gps(req.file.path).catch(() => null)
      if (exif && exif.latitude && exif.longitude) { latNum = exif.latitude; lngNum = exif.longitude }
    }
    if (latNum == null || lngNum == null) return res.status(400).json({ error: 'Missing coordinates' })
    const vesselInfo = resolveCatchVesselLocal(req.body)
    const item = {
      id: nanoid(), userId: req.user.id,
      species: species || 'unknown', netType: netType || null, weightKg: weightKg ? parseFloat(weightKg) : null,
      lengthCm: lengthCm ? parseFloat(lengthCm) : null, gear: gear || null,
      hoursFished: hoursFished != null ? (isFinite(parseFloat(hoursFished)) ? parseFloat(hoursFished) : null) : null,
      numHooksPanels: numHooksPanels != null ? (isFinite(parseInt(numHooksPanels)) ? parseInt(numHooksPanels) : null) : null,
      numHauls: numHauls != null ? (isFinite(parseInt(numHauls)) ? parseInt(numHauls) : null) : null,
      vesselId: vesselInfo.vesselId,
      vessel: vesselInfo.vessel,
      vesselRegistrationNumber: vesselInfo.vesselRegistrationNumber,
      vesselName: vesselInfo.vesselName,
      ownerName: vesselInfo.ownerName,
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
    res.json(enrichCatchWithVesselLocal(item))
  } catch (e) {
    res.status(500).json({ error: 'Upload failed' })
  }
})

app.get('/api/catches/me', auth(), async (req, res) => {
  const items = catchesDb.get('catches').filter(c => c.userId === req.user.id).value()
  res.json(items.map(enrichCatchWithVesselLocal))
})

app.get('/api/catches', auth('admin'), async (req, res) => {
  const { userId, vesselId, from, to } = req.query
  let allC = catchesDb.get('catches').value()
  if (userId) allC = allC.filter(c => c.userId === userId)
  if (vesselId && vesselId !== '__unassigned__') {
    const vid = String(vesselId)
    allC = allC.filter(c => {
      const cVid = c.vesselId ? String(c.vesselId) : null
      const cReg = c.vesselRegistrationNumber ? String(c.vesselRegistrationNumber).trim().toLowerCase() : null
      const cName = c.vesselName ? String(c.vesselName).trim().toLowerCase() : null
      return cVid === vid || cReg === vid.trim().toLowerCase() || cName === vid.trim().toLowerCase()
    })
  } else if (vesselId === '__unassigned__') {
    allC = allC.filter(c => !c.vesselId && !c.vessel && !c.vesselName && !c.vesselRegistrationNumber)
  }
  if (from) allC = allC.filter(c => new Date(c.capturedAt || c.createdAt) >= new Date(from))
  if (to) allC = allC.filter(c => new Date(c.capturedAt || c.createdAt) <= new Date(to))
  const allU = usersDb.get('users').value()
  const list = allC.map(c => ({
    ...enrichCatchWithVesselLocal(c),
    user: allU.find(u => u.id === c.userId) ? { id: c.userId, name: allU.find(u => u.id === c.userId).name, email: allU.find(u => u.id === c.userId).email } : null
  })).sort((a, b) => new Date(b.capturedAt || b.createdAt) - new Date(a.capturedAt || a.createdAt))
  res.json(list)
})

app.patch('/api/admin/catches/:id', auth('admin'), async (req, res) => {
  const id = req.params.id
  const allowed = ['species','weightKg','lengthCm','gear','note','netType','hoursFished','numHooksPanels','numHauls']
  const updates = {}
  allowed.forEach(k => { if (req.body[k] !== undefined) updates[k] = req.body[k] })
  if (req.body.vesselId !== undefined) {
    try {
      const vesselInfo = resolveCatchVesselLocal(req.body)
      Object.assign(updates, {
        vesselId: vesselInfo.vesselId,
        vessel: vesselInfo.vessel,
        vesselRegistrationNumber: vesselInfo.vesselRegistrationNumber,
        vesselName: vesselInfo.vesselName,
        ownerName: vesselInfo.ownerName
      })
    } catch (e) {
      return res.status(e.statusCode || 400).json({ error: e.message })
    }
  }
  const exists = catchesDb.get('catches').find({ id }).value(); if (!exists) return res.status(404).json({ error: 'Not found' })
  catchesDb.get('catches').find({ id }).assign(updates).write(); res.json({ ok: true })
})

app.delete('/api/admin/catches/:id', auth('admin'), async (req, res) => {
  const id = req.params.id
  const exists = catchesDb.get('catches').find({ id }).value(); if (!exists) return res.status(404).json({ error: 'Not found' })
  catchesDb.set('catches', catchesDb.get('catches').filter(c => c.id !== id).value()).write(); res.json({ ok: true })
})

app.patch('/api/catches/:id', auth(), async (req, res) => {
  const id = req.params.id
  const exists = catchesDb.get('catches').find({ id }).value()
  if (!exists) return res.status(404).json({ error: 'Not found' })
  if (!isSelfOrAdmin(req, exists.userId)) return res.status(403).json({ error: 'Forbidden' })
  const allowed = ['species','weightKg','lengthCm','gear','note','netType','hoursFished','numHooksPanels','numHauls']
  const updates = {}
  allowed.forEach(k => { if (req.body[k] !== undefined) updates[k] = req.body[k] })
  if (req.body.vesselId !== undefined) {
    try {
      const vesselInfo = resolveCatchVesselLocal(req.body)
      Object.assign(updates, {
        vesselId: vesselInfo.vesselId,
        vessel: vesselInfo.vessel,
        vesselRegistrationNumber: vesselInfo.vesselRegistrationNumber,
        vesselName: vesselInfo.vesselName,
        ownerName: vesselInfo.ownerName
      })
    } catch (e) {
      return res.status(e.statusCode || 400).json({ error: e.message })
    }
  }
  catchesDb.get('catches').find({ id }).assign(updates).write(); res.json({ ok: true })
})

app.delete('/api/catches/:id', auth(), async (req, res) => {
  const id = req.params.id
  const exists = catchesDb.get('catches').find({ id }).value()
  if (!exists) return res.status(404).json({ error: 'Not found' })
  if (!isSelfOrAdmin(req, exists.userId)) return res.status(403).json({ error: 'Forbidden' })
  catchesDb.set('catches', catchesDb.get('catches').filter(c => c.id !== id).value()).write(); res.json({ ok: true })
})

app.get('/api/admin/catches/summary', auth('admin'), async (req, res) => {
  const allC = catchesDb.get('catches').value()
  const allV = vesselsDb.get('vessels').value() || []
  const lookupVesselInfo = (c) => {
    if (c.vesselId) {
      const v = allV.find(x => x.id === c.vesselId)
      if (v) return {
        vesselId: v.id,
        ownerName: v.owner_name || c.ownerName || null,
        barangay: v.barangay || c.barangay || null,
        registrationNumber: v.vessel_registration_number || c.vesselRegistrationNumber || null,
        vesselName: v.vessel_name || c.vesselName || c.vessel || null
      }
    }
    return {
      vesselId: c.vesselId || null,
      ownerName: c.ownerName || null,
      barangay: c.barangay || null,
      registrationNumber: c.vesselRegistrationNumber || null,
      vesselName: c.vesselName || c.vessel || null
    }
  }
  const byVessel = new Map()
  allC.forEach(c => {
    const info = lookupVesselInfo(c)
    const rawKey = [
      info.vesselId || '',
      info.registrationNumber || '',
      info.vesselName || '',
      info.ownerName || ''
    ].join('||')
    let key
    if (info.vesselId) key = 'id:' + info.vesselId
    else if (info.registrationNumber) key = 'reg:' + info.registrationNumber
    else if (info.vesselName) key = 'name:' + info.vesselName
    else key = '__unassigned__'
    const t = new Date(c.capturedAt || c.createdAt || 0).getTime()
    const cur = byVessel.get(key)
    if (!cur) {
      byVessel.set(key, {
        vesselId: info.vesselId,
        ownerName: info.ownerName,
        barangay: info.barangay,
        registrationNumber: info.registrationNumber,
        vesselName: info.vesselName,
        latestSpecies: c.species || null,
        latestCapturedAt: c.capturedAt || c.createdAt,
        _t: t,
        totalCatches: 1,
        latestUserId: c.userId || null
      })
    } else {
      cur.totalCatches += 1
      if (t > cur._t) {
        cur._t = t
        cur.latestSpecies = c.species || null
        cur.latestCapturedAt = c.capturedAt || c.createdAt
        cur.latestUserId = c.userId || null
      }
      if (!cur.ownerName && info.ownerName) cur.ownerName = info.ownerName
      if (!cur.barangay && info.barangay) cur.barangay = info.barangay
      if (!cur.registrationNumber && info.registrationNumber) cur.registrationNumber = info.registrationNumber
      if (!cur.vesselName && info.vesselName) cur.vesselName = info.vesselName
      if (!cur.vesselId && info.vesselId) cur.vesselId = info.vesselId
    }
  })
  const out = Array.from(byVessel.values()).map(x => {
    const { _t, ...rest } = x
    return rest
  }).sort((a, b) => {
    const aT = a.latestCapturedAt ? new Date(a.latestCapturedAt).getTime() : 0
    const bT = b.latestCapturedAt ? new Date(b.latestCapturedAt).getTime() : 0
    return bT - aT
  })
  res.json(out)
})

app.delete('/api/admin/catches/user/:userId', auth('admin'), async (req, res) => {
  const userId = String(req.params.userId)
  const exists = catchesDb.get('catches').filter(c => c.userId === userId).value()
  if (!exists || exists.length === 0) return res.status(404).json({ error: 'No catches found for this user' })
  catchesDb.set('catches', catchesDb.get('catches').filter(c => c.userId !== userId).value()).write()
  res.json({ ok: true, deleted: exists.length })
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
    .sort((a, b) => new Date(b.recordedAt) - new Date(a.recordedAt))
  res.json(points)
})

app.get('/api/admin/users', auth('admin'), async (req, res) => {
  const all = usersDb.get('users').value()
  res.json(all.map(u => ({ id: u.id, name: u.name, email: u.email, role: u.role, barangay: u.barangay || null, vessel_name: u.vessel_name || null, fisher_id: u.fisher_id || null, createdAt: u.createdAt })))
})

app.post('/api/admin/users', auth('admin'), async (req, res) => {
  let { name, email, password, role } = req.body
  if (!name || !email || !password) return res.status(400).json({ error: 'Missing fields' })
  email = String(email).trim().toLowerCase()
  const exists = findUserByEmail(usersDb.get('users').value() || [], email)
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
  const userId = req.query && req.query.userId != null ? String(req.query.userId) : null
  let pts = tracksDb.get('tracks').value()
  if (userId) pts = pts.filter(t => String(t.userId) === userId)
  const us = usersDb.get('users').value()
  const points = pts.map(p => ({
    ...p,
    user: us.find(u => u.id === p.userId) ? { id: p.userId, name: us.find(u => u.id === p.userId).name, email: us.find(u => u.id === p.userId).email } : null
  })).sort((a, b) => new Date(b.recordedAt) - new Date(a.recordedAt))
  res.json(points)
})
app.get('/api/admin/tracks/summary', auth('admin'), async (req, res) => {
  const pts = tracksDb.get('tracks').value()
  const us = usersDb.get('users').value()
  const byUser = new Map()
  pts.forEach(p => {
    const uid = String(p.userId || 'unknown')
    const cur = byUser.get(uid)
    const t = new Date(p.recordedAt || 0).getTime()
    if (!cur || t > cur._t) {
      const next = { ...p, _t: t, total: (cur ? cur.total : 0) + 1 }
      byUser.set(uid, next)
    } else {
      cur.total = (cur ? cur.total : 0) + 1
    }
  })
  const out = Array.from(byUser.values()).map(p => {
    const u = us.find(x => x.id === p.userId)
    return {
      userId: p.userId,
      userName: u ? u.name : null,
      userEmail: u ? u.email : null,
      latestLat: p.lat,
      latestLng: p.lng,
      latestRecordedAt: p.recordedAt,
      totalTracks: p.total
    }
  }).sort((a, b) => {
    const aT = a.latestRecordedAt ? new Date(a.latestRecordedAt).getTime() : 0
    const bT = b.latestRecordedAt ? new Date(b.latestRecordedAt).getTime() : 0
    return bT - aT
  })
  res.json(out)
})
app.delete('/api/admin/tracks/user/:userId', auth('admin'), async (req, res) => {
  const userId = String(req.params.userId)
  const exists = tracksDb.get('tracks').filter(t => String(t.userId) === userId).value()
  if (!exists || exists.length === 0) return res.status(404).json({ error: 'No tracks found for this user' })
  tracksDb.set('tracks', tracksDb.get('tracks').filter(t => String(t.userId) !== userId).value()).write()
  res.json({ ok: true, deleted: exists.length })
})
app.get('/api/admin/status_history', auth(['admin','inspector']), async (req, res) => {
  const userId = req.query && req.query.userId != null ? String(req.query.userId) : null
  const limitRaw = req.query && req.query.limit != null ? Number(req.query.limit) : 200
  const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(1000, Math.floor(limitRaw))) : 200
  const us = usersDb.get('users').value()
  let list = statusDb.get('status_events').value() || []
  if (!isAdmin(req.user)) {
    const selfId = String(req.user.id || '')
    if (userId && userId !== selfId) return res.status(403).json({ error: 'Forbidden' })
    list = list.filter(e => String(e.userId || '') === selfId)
  } else if (userId) {
    list = list.filter(e => String(e.userId || '') === userId)
  }
  list = list.slice().sort((a, b) => new Date(b.at || 0) - new Date(a.at || 0)).slice(0, limit)
  const out = list.map(e => {
    const u = us.find(x => x.id === e.userId)
    return { ...e, user: u ? { id: u.id, name: u.name, email: u.email } : null }
  })
  res.json(out)
})
app.get('/api/users', auth('admin'), async (req, res) => {
  const all = usersDb.get('users').value()
  res.json(all.map(u => ({ id: u.id, name: u.name, email: u.email, role: u.role, barangay: u.barangay || null, vessel_name: u.vessel_name || null, fisher_id: u.fisher_id || null, createdAt: u.createdAt })))
})

app.get('/api/live_locations', auth(), (req, res) => {
  const pts = tracksDb.get('tracks').value()
  const us = usersDb.get('users').value()
  const currentUserId = String(req.user.id)

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
  const activeUserIds = new Set()
  trackingStateByUserId.forEach((v, k) => { if (v.active) activeUserIds.add(String(k)) })
  const active = Array.from(latestByUserId.values()).filter(p => String(p.userId) === currentUserId && activeUserIds.has(String(p.userId))).map(p => { delete p._t; return { ...p, active: true } })
  res.json(active)
})

app.get('/api/status_history', auth(), async (req, res) => {
  const userId = req.query && req.query.userId != null ? String(req.query.userId) : null
  const limitRaw = req.query && req.query.limit != null ? Number(req.query.limit) : 200
  const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(1000, Math.floor(limitRaw))) : 200
  const us = usersDb.get('users').value()
  let list = statusDb.get('status_events').value() || []
  if (!isAdmin(req.user)) {
    const selfId = String(req.user.id || '')
    if (userId && userId !== selfId) return res.status(403).json({ error: 'Forbidden' })
    list = list.filter(e => String(e.userId || '') === selfId)
  } else if (userId) {
    list = list.filter(e => String(e.userId || '') === userId)
  }
  list = list.slice().sort((a, b) => new Date(b.at || 0) - new Date(a.at || 0)).slice(0, limit)
  const out = list.map(e => {
    const u = us.find(x => x.id === e.userId)
    return { ...e, user: u ? { id: u.id, name: u.name, email: u.email } : null }
  })
  res.json(out)
})

app.get('/api/admin/live_locations', auth(['admin', 'inspector']), (req, res) => {
  const pts = tracksDb.get('tracks').value()
  const us = usersDb.get('users').value()
  const vs = vesselsDb.get('vessels').value()
  const selfId = isAdmin(req.user) ? null : String(req.user.id || '')

  const latestByUserId = new Map()
  statusStateByUserId.forEach((st, userId) => {
    if (!st || !userId) return
    if (selfId && String(userId) !== selfId) return
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
    if (selfId && userId !== selfId) return
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
      
      // Find vessel info for this user
      let vesselInfo = null
      if (rest.vesselId) {
        vesselInfo = vs.find(v => v.id === rest.vesselId)
      }
      if (!vesselInfo && rest.vesselRegistrationNumber) {
        vesselInfo = vs.find(v => v.vessel_registration_number === rest.vesselRegistrationNumber)
      }
      // Try to find vessel linked to the user
      if (!vesselInfo && u) {
        vesselInfo = vs.find(v => v.owner_name && v.owner_name.toLowerCase().includes((u.name || '').toLowerCase()))
      }
      
      return { 
        ...rest, 
        active, 
        lastSeenAt, 
        status: statusState.status, 
        statusAt: statusState.at, 
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
async function fetchTileWithTimeout(url, timeoutMs = 4000) {
  if (typeof fetch !== 'function') return null
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const r = await fetch(url, { redirect: 'follow', signal: controller.signal, headers: { 'User-Agent': 'capstone-pro' } })
    if (!r.ok) return null
    return {
      status: r.status,
      contentType: r.headers.get('content-type') || 'image/png',
      body: Buffer.from(await r.arrayBuffer())
    }
  } catch {
    return null
  } finally {
    clearTimeout(timer)
  }
}
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
    let contentType = 'image/png'
    let body = null

    const fetched = await fetchTileWithTimeout(upstream, 4000)
    if (fetched) {
      contentType = fetched.contentType
      body = fetched.body
    }

    if (!body) {
      res.setHeader('Content-Type', 'image/png')
      res.setHeader('Cache-Control', 'public, max-age=60')
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
  const hb = setInterval(() => {
    if (!res.destroyed) {
      res.write(':\n\n')
    }
  }, 30000)
  
  req.on('close', () => {
    clearInterval(hb)
    const i = sseClients.indexOf(res)
    if (i >= 0) sseClients.splice(i,1)
  })
  req.on('error', () => {
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
} else if (require.main === module) {
  startServer(BASE_PORT)
} else {
  module.exports = app
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
  if (!isAdmin(req.user)) {
    const selfId = String(req.user.id || '')
    if (userId && String(userId) !== selfId) return res.status(403).json({ error: 'Forbidden' })
    list = list.filter(a => String(a.user_id || '') === selfId)
  } else if (userId) {
    list = list.filter(a => String(a.user_id || '') === String(userId))
  }
  if (type) list = list.filter(a => a.type === type)
  if (from) list = list.filter(a => new Date(a.created_at) >= new Date(from))
  if (to) list = list.filter(a => new Date(a.created_at) <= new Date(to))
  list.sort((a,b) => new Date(b.created_at) - new Date(a.created_at))
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
  if (!isSelfOrAdmin(req, exists.user_id)) return res.status(403).json({ error: 'Forbidden' })
  activityDb.set('activity_logs', activityDb.get('activity_logs').filter(a => a.id !== id).value()).write()
  res.json({ ok: true })
})
app.get('/api/admin/activity_insights', auth(['admin','inspector']), (req, res) => {
  let logs = activityDb.get('activity_logs').value()
  if (!isAdmin(req.user)) {
    const selfId = String(req.user.id || '')
    logs = logs.filter(a => String(a.user_id || '') === selfId)
  }
  const zones = zonesDb.get('zones').value() || []
  const areas = protectedAreasDb.get('protected_areas').value() || []
  let illegalProtected = 0
  const illegalTypes = ['illegal_fishing','unauthorized_structures','illegal_dumping']
  logs.forEach(a => {
    if (illegalTypes.includes(a.type)) {
      const turf = require('@turf/turf')
      const pt = turf.point([a.location.lng, a.location.lat])
      const polys = [
        ...(zones || []).map(z => z.geometry ? { type: 'Feature', geometry: z.geometry } : null).filter(Boolean),
        ...(areas || []).map(ar => ar.geom ? { type: 'Feature', geometry: ar.geom } : null).filter(Boolean)
      ]
      if (polys.some(poly => { try { return turf.booleanPointInPolygon(pt, poly) } catch { return false } })) illegalProtected++
    }
  })
  let alerts = alertsDb.get('alerts').value() || []
  if (!isAdmin(req.user)) {
    const selfId = String(req.user.id || '')
    alerts = alerts.filter(a => String(a.userId || '') === selfId)
  }
  const weekAgo = Date.now() - 7*24*60*60*1000
  const approaches = alerts.filter(a => a.type === 'approach' && new Date(a.recordedAt || 0).getTime() >= weekAgo).length
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

app.use((err, req, res, next) => {
  try { console.error('handler_error', err) } catch {}
  if (!res.headersSent) res.status(500).json({ error: 'Internal error' })
})

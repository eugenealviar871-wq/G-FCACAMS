require('dotenv').config({ path: path.join(__dirname, '../.env') })
const { createClient } = require('@supabase/supabase-js')
const fs = require('fs')
const path = require('path')

const SUPABASE_URL = process.env.SUPABASE_URL
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY // Prefer Service Role for admin tasks

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error('Error: SUPABASE_URL and SUPABASE_ANON_KEY (or SUPABASE_SERVICE_ROLE_KEY) are required in .env')
  console.error('Please add them to your .env file.')
  process.exit(1)
}

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY)

const DATA_DIR = path.join(__dirname, '../data')
const UPLOADS_DIR = path.join(__dirname, '../uploads')

// Helper to read JSON
function readJson(filename) {
  try {
    const p = path.join(DATA_DIR, filename)
    if (!fs.existsSync(p)) return []
    const content = fs.readFileSync(p, 'utf8')
    const json = JSON.parse(content)
    // LowDB structure often has a key matching the filename (e.g. users.json -> { users: [...] })
    const key = Object.keys(json)[0]
    return Array.isArray(json) ? json : (json[key] || [])
  } catch (e) {
    console.error(`Error reading ${filename}:`, e.message)
    return []
  }
}

const idMap = new Map() // Old ID -> New UUID

async function migrateUsers() {
  console.log('Migrating Users...')
  const users = readJson('users.json')
  
  for (const user of users) {
    console.log(`Processing user: ${user.email}`)
    
    // 1. Create User in Supabase Auth
    // We use a temporary password since we can't migrate hashed passwords
    const tempPassword = 'ChangeMe123!' 
    
    // Try to create user
    // If using Service Role, we can use admin.createUser which auto-confirms
    let authUser = null
    let error = null
    
    // Check if we have admin rights (simple check if key starts with 'ey...')
    // But supabase-js client figures it out.
    
    // Try admin approach first if available
    if (supabase.auth.admin) {
        const { data, error: err } = await supabase.auth.admin.createUser({
            email: user.email,
            password: tempPassword,
            email_confirm: true,
            user_metadata: {
                name: user.name,
                role: user.role,
                barangay: user.barangay
            }
        })
        if (data && data.user) authUser = data.user
        else if (err && err.message.includes('already has been registered')) {
            // If exists, we can't get the ID easily without admin.listUsers
            // Try to find via listUsers (only works with service role)
            const { data: list } = await supabase.auth.admin.listUsers()
            const found = list.users.find(u => u.email === user.email)
            if (found) authUser = found
        }
        if (err && !authUser) error = err
    } else {
        // Fallback to public signUp
        const { data, error: err } = await supabase.auth.signUp({
            email: user.email,
            password: tempPassword,
            options: {
                data: {
                    name: user.name,
                    role: user.role,
                    barangay: user.barangay
                }
            }
        })
        if (data && data.user) authUser = data.user
        if (err) error = err
    }

    if (authUser) {
      idMap.set(user.id, authUser.id)
      console.log(`  -> Mapped ${user.id} to ${authUser.id}`)
      
      // Update Profile (Trigger might have done it, but ensure role is correct)
      const { error: profileErr } = await supabase.from('profiles').upsert({
          id: authUser.id,
          email: user.email,
          name: user.name,
          role: user.role || 'fisher',
          barangay: user.barangay
      })
      if (profileErr) console.error('  -> Profile Update Error:', profileErr.message)
      
    } else {
      console.error(`  -> Failed to migrate user ${user.email}:`, error ? error.message : 'Unknown error')
    }
  }
}

async function migrateTracks() {
  console.log('Migrating Tracks...')
  const tracks = readJson('tracks.json')
  const batch = []
  
  for (const t of tracks) {
    const newUserId = idMap.get(t.userId)
    if (!newUserId) continue
    
    batch.push({
        user_id: newUserId,
        lat: t.lat,
        lng: t.lng,
        accuracy: t.accuracy,
        speed: t.speed,
        heading: t.heading,
        active: t.active,
        recorded_at: t.recordedAt || new Date().toISOString()
    })
    
    if (batch.length >= 100) {
        const { error } = await supabase.from('tracks').insert(batch)
        if (error) console.error('  -> Batch Insert Error:', error.message)
        batch.length = 0
    }
  }
  
  if (batch.length > 0) {
      const { error } = await supabase.from('tracks').insert(batch)
      if (error) console.error('  -> Final Batch Insert Error:', error.message)
  }
  console.log('Tracks migration done.')
}

async function migrateStatusEvents() {
  console.log('Migrating Status Events...')
  const events = readJson('status_events.json')
  const batch = []
  
  for (const e of events) {
    const newUserId = idMap.get(e.userId)
    if (!newUserId) continue
    
    batch.push({
        user_id: newUserId,
        status: e.status,
        lat: e.lat,
        lng: e.lng,
        at: e.at || e.recordedAt
    })
    
    if (batch.length >= 100) {
        const { error } = await supabase.from('status_events').insert(batch)
        if (error) console.error('  -> Batch Insert Error:', error.message)
        batch.length = 0
    }
  }
  if (batch.length > 0) {
      const { error } = await supabase.from('status_events').insert(batch)
      if (error) console.error('  -> Final Batch Insert Error:', error.message)
  }
  console.log('Status Events migration done.')
}

async function migrateCatches() {
  console.log('Migrating Catches...')
  const catches = readJson('catches.json')
  const images = readJson('images.json')
  
  for (const c of catches) {
    const newUserId = idMap.get(c.userId)
    if (!newUserId) continue // Skip if user not found
    
    let imageUrl = null
    
    // Find image
    // Old images.json: { catch_id: "...", bucket_key: "/uploads/hash" }
    // Or check c.photoUrl
    
    let imageFile = null
    if (c.photoUrl) {
        // Assume it's a path
        imageFile = path.basename(c.photoUrl)
    } else {
        const imgEntry = images.find(i => i.catch_id === c.id)
        if (imgEntry && imgEntry.bucket_key) {
            imageFile = path.basename(imgEntry.bucket_key)
        }
    }
    
    if (imageFile) {
        const localPath = path.join(UPLOADS_DIR, imageFile)
        if (fs.existsSync(localPath)) {
            console.log(`  -> Uploading image for catch ${c.species}...`)
            try {
                const fileContent = fs.readFileSync(localPath)
                // Upload to Supabase Storage
                // Using a simpler name: userId/timestamp_hash
                const newName = `${newUserId}/${Date.now()}_${imageFile}`
                const { data, error } = await supabase.storage.from('uploads').upload(newName, fileContent, {
                    contentType: 'image/jpeg' // Guessing content type, exifr might help if installed but let's default
                })
                
                if (!error && data) {
                    const { data: { publicUrl } } = supabase.storage.from('uploads').getPublicUrl(newName)
                    imageUrl = publicUrl
                } else {
                    console.error('     Upload Failed:', error ? error.message : 'Unknown')
                }
            } catch (e) {
                console.error('     File Read Error:', e.message)
            }
        }
    }
    
    // Insert Catch
    const { error } = await supabase.from('catches').insert({
        user_id: newUserId,
        species: c.species,
        weight: c.weightKg,
        length: c.lengthCm,
        image_url: imageUrl,
        notes: c.note,
        lat: c.lat,
        lng: c.lng,
        recorded_at: c.capturedAt || c.createdAt
    })
    
    if (error) console.error(`  -> Failed to insert catch: ${error.message}`)
  }
  console.log('Catches migration done.')
}

async function main() {
  try {
    await migrateUsers()
    await migrateTracks()
    await migrateStatusEvents()
    await migrateCatches()
    console.log('------------------------------------------------')
    console.log('MIGRATION COMPLETED')
    console.log('Note: Users have been migrated with password: ChangeMe123!')
    console.log('Please inform users to change their password.')
  } catch (e) {
    console.error('Migration Failed:', e)
  }
}

main()

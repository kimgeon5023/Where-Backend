import { createHash, randomBytes, randomUUID, scryptSync, timingSafeEqual } from 'node:crypto'
import pg from 'pg'

const { Pool } = pg
const connectionString = process.env.DATABASE_URL?.trim()
const useSsl = process.env.DATABASE_SSL !== 'false'
const rejectUnauthorized = process.env.DATABASE_SSL_REJECT_UNAUTHORIZED === 'true'

if (!connectionString) {
  throw new Error('DATABASE_URL is required. Add the PostgreSQL connection URL to .env.')
}

export const siteId = process.env.SITE_ID?.trim() || 'where-main'

const database = new Pool({
  connectionString,
  ssl: useSsl ? { rejectUnauthorized } : false,
  max: Number(process.env.DATABASE_POOL_SIZE || 10),
  connectionTimeoutMillis: 10_000,
  idleTimeoutMillis: 30_000,
})

function toIsoString(value) {
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString()
}

function toUser(row) {
  return {
    id: row.id,
    name: row.name,
    email: row.email || `${row.username}@where-to-go.local`,
    provider: row.provider,
    profileImage: row.profile_image,
    sourceSite: row.source_site,
    createdAt: toIsoString(row.created_at),
    lastLoginAt: row.last_login_at ? toIsoString(row.last_login_at) : null,
  }
}

function passwordRecord(password) {
  const salt = randomBytes(16).toString('hex')
  return { salt, hash: scryptSync(password, salt, 64).toString('hex') }
}

function passwordMatches(password, hash, salt) {
  if (!hash || !salt) return false
  const expected = Buffer.from(hash, 'hex')
  const actual = Buffer.from(scryptSync(password, salt, 64).toString('hex'), 'hex')
  return expected.length === actual.length && timingSafeEqual(expected, actual)
}

export async function initializeDatabase() {
  await database.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY,
      username VARCHAR(20) NOT NULL UNIQUE,
      name VARCHAR(20) NOT NULL,
      password_hash TEXT NOT NULL,
      password_salt TEXT NOT NULL,
      provider TEXT NOT NULL DEFAULT 'password',
      profile_image TEXT NOT NULL DEFAULT '',
      source_site TEXT NOT NULL DEFAULT 'legacy',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_login_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `)
  await database.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS source_site TEXT NOT NULL DEFAULT 'legacy'`)
  await database.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT`)
  await database.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS provider_user_id TEXT`)
  await database.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`)
  await database.query(`ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL`)
  await database.query(`ALTER TABLE users ALTER COLUMN password_salt DROP NOT NULL`)
  await database.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS users_provider_identity_idx
    ON users (provider, provider_user_id)
    WHERE provider_user_id IS NOT NULL
  `)
  await database.query(`CREATE INDEX IF NOT EXISTS users_source_site_idx ON users (source_site)`)
  await database.query(`CREATE INDEX IF NOT EXISTS users_created_at_idx ON users (created_at DESC)`)
  await database.query(`
    CREATE TABLE IF NOT EXISTS friendships (
      id UUID PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      friend_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (user_id, friend_id),
      CHECK (user_id <> friend_id)
    )
  `)
  await database.query(`
    CREATE TABLE IF NOT EXISTS relationship_requests (
      id UUID PRIMARY KEY,
      sender_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      recipient_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      relationship_type TEXT NOT NULL CHECK (relationship_type IN ('friend', 'couple', 'family')),
      status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'rejected')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      responded_at TIMESTAMPTZ
    )
  `)
  await database.query(`CREATE INDEX IF NOT EXISTS relationship_requests_recipient_idx ON relationship_requests (recipient_id, status, created_at DESC)`)
  await database.query(`
    CREATE TABLE IF NOT EXISTS trips (
      id UUID PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title VARCHAR(120) NOT NULL,
      start_area TEXT NOT NULL DEFAULT '',
      date_start DATE,
      date_end DATE,
      companion TEXT NOT NULL DEFAULT 'alone',
      headcount SMALLINT NOT NULL DEFAULT 1 CHECK (headcount >= 1 AND headcount <= 100),
      budget_per_person INTEGER NOT NULL DEFAULT 0 CHECK (budget_per_person >= 0),
      transport TEXT NOT NULL DEFAULT 'public' CHECK (transport IN ('public', 'car')),
      weather TEXT NOT NULL DEFAULT 'sunny',
      likes JSONB NOT NULL DEFAULT '[]'::jsonb,
      dislikes JSONB NOT NULL DEFAULT '[]'::jsonb,
      route_coordinates JSONB NOT NULL DEFAULT '[]'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `)
  await database.query(`
    CREATE TABLE IF NOT EXISTS trip_stops (
      id UUID PRIMARY KEY,
      trip_id UUID NOT NULL REFERENCES trips(id) ON DELETE CASCADE,
      stop_order SMALLINT NOT NULL CHECK (stop_order >= 0),
      place_id TEXT,
      place_name TEXT NOT NULL,
      category TEXT NOT NULL DEFAULT 'tour',
      area TEXT NOT NULL DEFAULT '',
      latitude DOUBLE PRECISION NOT NULL CHECK (latitude >= -90 AND latitude <= 90),
      longitude DOUBLE PRECISION NOT NULL CHECK (longitude >= -180 AND longitude <= 180),
      estimated_cost INTEGER NOT NULL DEFAULT 0 CHECK (estimated_cost >= 0),
      duration_min INTEGER NOT NULL DEFAULT 0 CHECK (duration_min >= 0),
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (trip_id, stop_order)
    )
  `)
  await database.query(`CREATE INDEX IF NOT EXISTS trips_user_updated_idx ON trips (user_id, updated_at DESC)`)
  await database.query(`CREATE INDEX IF NOT EXISTS trip_stops_trip_order_idx ON trip_stops (trip_id, stop_order)`)
}

export async function createPasswordUser({ username, name, password }) {
  const id = randomUUID()
  const { salt, hash } = passwordRecord(password)

  try {
    const result = await database.query(
      `INSERT INTO users
        (id, username, name, password_hash, password_salt, provider, profile_image, source_site)
       VALUES ($1, $2, $3, $4, $5, 'password', '', $6)
       RETURNING id, username, name, email, provider, profile_image, source_site, created_at`,
      [id, username, name, hash, salt, siteId],
    )
    return toUser(result.rows[0])
  } catch (error) {
    if (error?.code === '23505') {
      const duplicate = new Error('USERNAME_ALREADY_EXISTS')
      duplicate.code = 'USERNAME_ALREADY_EXISTS'
      throw duplicate
    }
    throw error
  }
}

export async function authenticatePasswordUser({ username, password }) {
  const result = await database.query(
    `SELECT id, username, name, email, password_hash, password_salt, provider, profile_image, source_site, created_at, last_login_at
     FROM users WHERE username = $1 AND provider = 'password'`,
    [username],
  )
  const user = result.rows[0]
  if (!user || !passwordMatches(password, user.password_hash, user.password_salt)) {
    const error = new Error('INVALID_CREDENTIALS')
    error.code = 'INVALID_CREDENTIALS'
    throw error
  }
  const updated = await database.query(
    `UPDATE users SET last_login_at = NOW() WHERE id = $1
     RETURNING id, username, name, email, provider, profile_image, source_site, created_at, last_login_at`,
    [user.id],
  )
  return toUser(updated.rows[0])
}

export async function changePassword({ userId, currentPassword, newPassword }) {
  const result = await database.query(
    `SELECT id, username, name, email, password_hash, password_salt, provider, profile_image, source_site, created_at, last_login_at
     FROM users WHERE id = $1`,
    [userId],
  )
  const user = result.rows[0]
  if (!user) {
    const error = new Error('USER_NOT_FOUND')
    error.code = 'USER_NOT_FOUND'
    throw error
  }
  if (user.provider !== 'password') {
    const error = new Error('PASSWORD_AUTH_UNAVAILABLE')
    error.code = 'PASSWORD_AUTH_UNAVAILABLE'
    throw error
  }
  if (!passwordMatches(currentPassword, user.password_hash, user.password_salt)) {
    const error = new Error('CURRENT_PASSWORD_INVALID')
    error.code = 'CURRENT_PASSWORD_INVALID'
    throw error
  }
  const { salt, hash } = passwordRecord(newPassword)
  const updated = await database.query(
    `UPDATE users SET password_hash = $1, password_salt = $2 WHERE id = $3
     RETURNING id, username, name, email, provider, profile_image, source_site, created_at, last_login_at`,
    [hash, salt, userId],
  )
  return toUser(updated.rows[0])
}

export async function updateUserProfile({ userId, name, profileImage }) {
  const result = await database.query(
    `UPDATE users SET name = $1, profile_image = $2 WHERE id = $3
     RETURNING id, username, name, email, provider, profile_image, source_site, created_at, last_login_at`,
    [name, profileImage, userId],
  )
  if (!result.rowCount) {
    const error = new Error('USER_NOT_FOUND')
    error.code = 'USER_NOT_FOUND'
    throw error
  }
  return toUser(result.rows[0])
}

export async function deleteUser(userId) {
  const result = await database.query('DELETE FROM users WHERE id = $1', [userId])
  return result.rowCount > 0
}

function socialUsername(providerUserId) {
  const digest = createHash('sha256').update(`google:${providerUserId}`).digest('hex').slice(0, 18)
  return `g_${digest}`
}

function normalizedSocialName(name) {
  return Array.from(name?.trim().normalize('NFC') || 'Google 사용자').slice(0, 20).join('')
}

export async function upsertGoogleUser({ providerUserId, name, email, profileImage }) {
  const username = socialUsername(providerUserId)
  const result = await database.query(
    `INSERT INTO users
      (id, username, name, email, password_hash, password_salt, provider, provider_user_id, profile_image, source_site)
     VALUES ($1, $2, $3, $4, NULL, NULL, $5, $6, $7, $8)
     ON CONFLICT (provider, provider_user_id) WHERE provider_user_id IS NOT NULL
     DO UPDATE SET
       name = EXCLUDED.name,
       email = EXCLUDED.email,
       profile_image = EXCLUDED.profile_image,
       last_login_at = NOW()
     RETURNING id, username, name, email, provider, profile_image, source_site, created_at, last_login_at`,
    [
      randomUUID(),
      username,
      normalizedSocialName(name),
      email || null,
      'google',
      String(providerUserId),
      profileImage || '',
      siteId,
    ],
  )
  return toUser(result.rows[0])
}

export async function listUsers() {
  const result = await database.query(
    `SELECT id, name, username, email, provider, provider_user_id, profile_image, source_site, created_at, last_login_at
     FROM users
     ORDER BY created_at DESC`,
  )
  return result.rows.map(toUser)
}

export async function listOtherUsers(userId) {
  const result = await database.query(
    `SELECT id, name, username, email, provider, profile_image, source_site, created_at, last_login_at
     FROM users WHERE id <> $1 ORDER BY created_at DESC`,
    [userId],
  )
  return result.rows.map((row) => ({ ...toUser(row), username: row.username }))
}

export async function listFriends(userId) {
  const result = await database.query(
    `SELECT u.id, u.name, u.username, u.email, u.provider, u.profile_image, u.source_site, u.created_at, u.last_login_at,
      COALESCE(array_remove(array_agg(DISTINCT rr.relationship_type) FILTER (WHERE rr.status = 'accepted' AND (rr.sender_id = $1 OR rr.recipient_id = $1)), NULL), '{}') AS relationships
     FROM friendships f
     JOIN users u ON u.id = f.friend_id
     LEFT JOIN relationship_requests rr ON rr.status = 'accepted'
       AND ((rr.sender_id = $1 AND rr.recipient_id = u.id) OR (rr.recipient_id = $1 AND rr.sender_id = u.id))
     WHERE f.user_id = $1
     GROUP BY u.id
     ORDER BY u.name`,
    [userId],
  )
  return result.rows.map((row) => ({ ...toUser(row), username: row.username, relationships: row.relationships || [] }))
}

export async function addFriend(userId, friendId) {
  if (userId === friendId) throw new Error('CANNOT_ADD_SELF')
  const client = await database.connect()
  try {
    await client.query('BEGIN')
    await client.query('SELECT id FROM users WHERE id = $1', [friendId]).then((result) => {
      if (!result.rowCount) throw new Error('USER_NOT_FOUND')
    })
    await client.query('INSERT INTO friendships (id, user_id, friend_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING', [randomUUID(), userId, friendId])
    await client.query('INSERT INTO friendships (id, user_id, friend_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING', [randomUUID(), friendId, userId])
    await client.query('COMMIT')
  } catch (error) {
    await client.query('ROLLBACK')
    throw error
  } finally {
    client.release()
  }
}

export async function createRelationshipRequest(senderId, recipientId, relationshipType) {
  if (senderId === recipientId) throw new Error('CANNOT_ADD_SELF')
  const friendship = await database.query('SELECT 1 FROM friendships WHERE user_id = $1 AND friend_id = $2', [senderId, recipientId])
  if (!friendship.rowCount) throw new Error('NOT_FRIENDS')
  await database.query(
    `UPDATE relationship_requests SET status = 'rejected', responded_at = NOW()
     WHERE sender_id = $1 AND recipient_id = $2 AND relationship_type = $3 AND status = 'pending'`,
    [senderId, recipientId, relationshipType],
  )
  const result = await database.query(
    `INSERT INTO relationship_requests (id, sender_id, recipient_id, relationship_type)
     VALUES ($1, $2, $3, $4) RETURNING id, status, created_at`,
    [randomUUID(), senderId, recipientId, relationshipType],
  )
  return result.rows[0]
}

export async function listNotifications(userId) {
  const result = await database.query(
    `SELECT rr.id, rr.relationship_type, rr.status, rr.created_at, rr.responded_at,
      u.id AS sender_id, u.name AS sender_name, u.profile_image AS sender_profile_image
     FROM relationship_requests rr JOIN users u ON u.id = rr.sender_id
     WHERE rr.recipient_id = $1 ORDER BY rr.created_at DESC`,
    [userId],
  )
  return result.rows.map((row) => ({ id: row.id, relationshipType: row.relationship_type, status: row.status, createdAt: toIsoString(row.created_at), respondedAt: row.responded_at ? toIsoString(row.responded_at) : null, sender: { id: row.sender_id, name: row.sender_name, profileImage: row.sender_profile_image || '' } }))
}

export async function respondToRelationshipRequest(userId, requestId, accepted) {
  const client = await database.connect()
  try {
    await client.query('BEGIN')
    const found = await client.query('SELECT sender_id, recipient_id, relationship_type, status FROM relationship_requests WHERE id = $1 FOR UPDATE', [requestId])
    const request = found.rows[0]
    if (!request || request.recipient_id !== userId) throw new Error('REQUEST_NOT_FOUND')
    if (request.status !== 'pending') throw new Error('REQUEST_ALREADY_RESPONDED')
    await client.query('UPDATE relationship_requests SET status = $1, responded_at = NOW() WHERE id = $2', [accepted ? 'accepted' : 'rejected', requestId])
    if (accepted) {
      await client.query('INSERT INTO friendships (id, user_id, friend_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING', [randomUUID(), request.sender_id, request.recipient_id])
      await client.query('INSERT INTO friendships (id, user_id, friend_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING', [randomUUID(), request.recipient_id, request.sender_id])
    }
    await client.query('COMMIT')
    return { relationshipType: request.relationship_type, status: accepted ? 'accepted' : 'rejected' }
  } catch (error) {
    await client.query('ROLLBACK')
    throw error
  } finally {
    client.release()
  }
}

export async function closeDatabase() {
  await database.end()
}

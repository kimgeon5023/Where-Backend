import { createHash, randomBytes, randomUUID, scryptSync, timingSafeEqual } from 'node:crypto'
import { readFile, readdir } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import pg from 'pg'

const { Pool } = pg
const connectionString = process.env.DATABASE_URL?.trim()
const useSsl = process.env.DATABASE_SSL !== 'false'
const rejectUnauthorized = process.env.DATABASE_SSL_REJECT_UNAUTHORIZED === 'true'

if (!connectionString) {
  throw new Error('DATABASE_URL is required. Add the cloud PostgreSQL connection URL to Where/.env.')
}

export const siteId = process.env.SITE_ID?.trim() || 'where-main'

const database = new Pool({
  connectionString,
  ssl: useSsl ? { rejectUnauthorized } : false,
  max: Number(process.env.DATABASE_POOL_SIZE || 10),
  connectionTimeoutMillis: 10_000,
  idleTimeoutMillis: 30_000,
})

// 서울특별시 자치구만 지역 검색·선택의 기준으로 사용한다.
const seoulDistrictNames = [
  '강남구', '강동구', '강북구', '강서구', '관악구', '광진구', '구로구', '금천구', '노원구', '도봉구',
  '동대문구', '동작구', '마포구', '서대문구', '서초구', '성동구', '성북구', '송파구', '양천구', '영등포구',
  '용산구', '은평구', '종로구', '중구', '중랑구',
]

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
  await database.query(`
    CREATE TABLE IF NOT EXISTS seoul_areas (
      id INTEGER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `)
  await database.query(`CREATE INDEX IF NOT EXISTS seoul_areas_name_idx ON seoul_areas (name)`)
  await database.query(
    `INSERT INTO seoul_areas (name)
     SELECT DISTINCT unnest($1::text[])
     ON CONFLICT (name) DO NOTHING`,
    [seoulDistrictNames],
  )
  await database.query(`
    CREATE TABLE IF NOT EXISTS favorites (
      id UUID PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      place_id TEXT NOT NULL,
      place_name VARCHAR(255) NOT NULL,
      address TEXT NOT NULL DEFAULT '',
      category VARCHAR(100) NOT NULL DEFAULT 'tour',
      image_url TEXT NOT NULL DEFAULT '',
      latitude DOUBLE PRECISION,
      longitude DOUBLE PRECISION,
      place_data JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (user_id, place_id)
    )
  `)
  await database.query(`CREATE INDEX IF NOT EXISTS favorites_user_created_idx ON favorites (user_id, created_at DESC)`)
  await database.query(`
    CREATE TABLE IF NOT EXISTS place_reviews (
      id UUID PRIMARY KEY,
      user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      place_id TEXT NOT NULL,
      rating SMALLINT NOT NULL CHECK (rating BETWEEN 1 AND 5),
      content TEXT NOT NULL CHECK (char_length(content) <= 1000),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `)
  await database.query(`CREATE INDEX IF NOT EXISTS place_reviews_place_created_idx ON place_reviews (place_id, created_at DESC)`)
  await database.query(`CREATE INDEX IF NOT EXISTS place_reviews_created_idx ON place_reviews (created_at DESC)`)
}

function paginationValues(page, limit) {
  const safePage = Math.max(1, Math.floor(Number(page) || 1))
  const safeLimit = Math.min(50, Math.max(1, Math.floor(Number(limit) || 20)))
  return { page: safePage, limit: safeLimit, offset: (safePage - 1) * safeLimit }
}

export async function searchSeoulAreas(query, limit = 8) {
  const q = String(query || '').trim()
  if (!q) return []
  const safeLimit = Math.min(8, Math.max(1, Math.floor(Number(limit) || 8)))
  const result = await database.query(
    `SELECT id, name
     FROM seoul_areas
     WHERE name ILIKE $1
       AND name = ANY($4::text[])
     ORDER BY CASE WHEN name ILIKE $2 THEN 0 ELSE 1 END, char_length(name), name
     LIMIT $3`,
    [`%${q}%`, `${q}%`, safeLimit, seoulDistrictNames],
  )
  return result.rows
}

function toFavorite(row) {
  return {
    id: row.id,
    placeId: row.place_id,
    placeName: row.place_name,
    address: row.address,
    category: row.category,
    imageUrl: row.image_url,
    latitude: row.latitude,
    longitude: row.longitude,
    place: row.place_data || {},
    createdAt: toIsoString(row.created_at),
  }
}

export async function listFavorites(userId) {
  const result = await database.query(
    `SELECT id, place_id, place_name, address, category, image_url, latitude, longitude, place_data, created_at
     FROM favorites
     WHERE user_id = $1
     ORDER BY created_at DESC`,
    [userId],
  )
  return result.rows.map(toFavorite)
}

export async function upsertFavorite({ userId, placeId, placeName, address, category, imageUrl, latitude, longitude, placeData }) {
  const result = await database.query(
    `INSERT INTO favorites (id, user_id, place_id, place_name, address, category, image_url, latitude, longitude, place_data)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb)
     ON CONFLICT (user_id, place_id) DO UPDATE SET
       place_name = EXCLUDED.place_name,
       address = EXCLUDED.address,
       category = EXCLUDED.category,
       image_url = EXCLUDED.image_url,
       latitude = EXCLUDED.latitude,
       longitude = EXCLUDED.longitude,
       place_data = EXCLUDED.place_data
     RETURNING id, place_id, place_name, address, category, image_url, latitude, longitude, place_data, created_at`,
    [randomUUID(), userId, placeId, placeName, address, category, imageUrl, latitude, longitude, JSON.stringify(placeData)],
  )
  return toFavorite(result.rows[0])
}

export async function deleteFavorite({ userId, placeId }) {
  const result = await database.query(
    'DELETE FROM favorites WHERE user_id = $1 AND place_id = $2',
    [userId, placeId],
  )
  return result.rowCount > 0
}

export async function listCourses({ userId, page, limit }) {
  const paging = paginationValues(page, limit)
  const [courses, total] = await Promise.all([
    database.query(
      `SELECT t.id, t.title, t.description, t.start_area, t.date_start, t.date_end, t.companion, t.headcount,
        t.budget_per_person, t.transport, t.weather, t.is_public, t.share_token, t.created_at, t.updated_at,
        COUNT(s.id)::INTEGER AS stop_count
       FROM trips t LEFT JOIN trip_stops s ON s.trip_id = t.id
       WHERE t.user_id = $1
       GROUP BY t.id
       ORDER BY t.updated_at DESC
       LIMIT $2 OFFSET $3`,
      [userId, paging.limit, paging.offset],
    ),
    database.query(`SELECT COUNT(*)::INTEGER AS count FROM trips WHERE user_id = $1`, [userId]),
  ])
  return { data: courses.rows.map((row) => toTrip(row)), pagination: { ...paging, total: total.rows[0].count } }
}

function tripShareToken() {
  return randomBytes(18).toString('base64url')
}

function tripValues(input, shareToken) {
  return [
    input.title, input.description, input.startArea, input.dateStart || null, input.dateEnd || null,
    input.companion, input.headcount, input.budgetPerPerson, input.transport, input.weather,
    JSON.stringify(input.likes), JSON.stringify(input.dislikes), JSON.stringify(input.routeCoordinates),
    input.isPublic, shareToken,
  ]
}

async function insertTripStops(client, tripId, stops) {
  for (const [index, stop] of stops.entries()) {
    await client.query(
      `INSERT INTO trip_stops (id, trip_id, stop_order, place_id, place_name, category, area, latitude, longitude, estimated_cost, duration_min, metadata)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb)`,
      [randomUUID(), tripId, index, stop.placeId || null, stop.placeName, stop.category, stop.area, stop.latitude, stop.longitude, stop.estimatedCost, stop.durationMin, JSON.stringify(stop.metadata)],
    )
  }
}

function toTrip(row, stops = []) {
  return {
    id: row.id, title: row.title, description: row.description || '', startArea: row.start_area,
    dateStart: row.date_start, dateEnd: row.date_end, companion: row.companion, headcount: row.headcount,
    budgetPerPerson: row.budget_per_person, transport: row.transport, weather: row.weather,
    likes: row.likes || [], dislikes: row.dislikes || [], routeCoordinates: row.route_coordinates || [],
    isPublic: Boolean(row.is_public), shareToken: row.share_token || null,
    createdAt: toIsoString(row.created_at), updatedAt: toIsoString(row.updated_at), stopCount: Number(row.stop_count ?? stops.length),
    stops: stops.map((stop) => ({ id: stop.id, order: stop.stop_order, placeId: stop.place_id, placeName: stop.place_name, category: stop.category, area: stop.area, latitude: stop.latitude, longitude: stop.longitude, estimatedCost: stop.estimated_cost, durationMin: stop.duration_min, metadata: stop.metadata || {} })),
  }
}

async function tripDetail(client, where, values) {
  const trip = await client.query(`SELECT * FROM trips WHERE ${where}`, values)
  if (!trip.rowCount) return null
  const stops = await client.query('SELECT * FROM trip_stops WHERE trip_id = $1 ORDER BY stop_order', [trip.rows[0].id])
  return toTrip(trip.rows[0], stops.rows)
}

export async function createTrip({ userId, input }) {
  const client = await database.connect()
  try {
    await client.query('BEGIN')
    const id = randomUUID()
    const shareToken = input.isPublic ? tripShareToken() : null
    const result = await client.query(
      `INSERT INTO trips (id, user_id, title, description, start_area, date_start, date_end, companion, headcount, budget_per_person, transport, weather, likes, dislikes, route_coordinates, is_public, share_token)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::jsonb, $14::jsonb, $15::jsonb, $16, $17)
       RETURNING *`, [id, userId, ...tripValues(input, shareToken)],
    )
    await insertTripStops(client, id, input.stops)
    await client.query('COMMIT')
    return toTrip(result.rows[0], input.stops.map((stop, order) => ({ ...stop, stop_order: order })))
  } catch (error) { await client.query('ROLLBACK'); throw error } finally { client.release() }
}

export async function getTrip({ userId, tripId }) {
  return tripDetail(database, 'id = $1 AND user_id = $2', [tripId, userId])
}

export async function updateTrip({ userId, tripId, input }) {
  const client = await database.connect()
  try {
    await client.query('BEGIN')
    const existing = await client.query('SELECT share_token FROM trips WHERE id = $1 AND user_id = $2 FOR UPDATE', [tripId, userId])
    if (!existing.rowCount) { const error = new Error('TRIP_NOT_FOUND'); error.code = 'TRIP_NOT_FOUND'; throw error }
    const shareToken = input.isPublic ? (existing.rows[0].share_token || tripShareToken()) : null
    const result = await client.query(
      `UPDATE trips SET title = $1, description = $2, start_area = $3, date_start = $4, date_end = $5, companion = $6, headcount = $7, budget_per_person = $8, transport = $9, weather = $10, likes = $11::jsonb, dislikes = $12::jsonb, route_coordinates = $13::jsonb, is_public = $14, share_token = $15, updated_at = NOW()
       WHERE id = $16 AND user_id = $17 RETURNING *`, [...tripValues(input, shareToken), tripId, userId],
    )
    await client.query('DELETE FROM trip_stops WHERE trip_id = $1', [tripId])
    await insertTripStops(client, tripId, input.stops)
    await client.query('COMMIT')
    return toTrip(result.rows[0], input.stops.map((stop, order) => ({ ...stop, stop_order: order })))
  } catch (error) { await client.query('ROLLBACK'); throw error } finally { client.release() }
}

export async function deleteTrip({ userId, tripId }) {
  const result = await database.query('DELETE FROM trips WHERE id = $1 AND user_id = $2', [tripId, userId])
  return result.rowCount > 0
}

export async function getPublicTrip(shareToken) {
  return tripDetail(database, 'share_token = $1 AND is_public = TRUE', [shareToken])
}

export async function listReviews({ placeId, page, limit }) {
  const paging = paginationValues(page, limit)
  const values = placeId ? [placeId, paging.limit, paging.offset] : [paging.limit, paging.offset]
  const where = placeId ? 'WHERE r.place_id = $1' : ''
  const limitIndex = placeId ? '$2' : '$1'
  const offsetIndex = placeId ? '$3' : '$2'
  const [reviews, total] = await Promise.all([
    database.query(
      `SELECT r.id, r.place_id, r.rating, r.content, r.image_url, r.created_at, r.updated_at,
        u.id AS user_id, u.name AS user_name, u.profile_image AS user_profile_image
       FROM place_reviews r LEFT JOIN users u ON u.id = r.user_id
       ${where}
       ORDER BY r.created_at DESC
       LIMIT ${limitIndex} OFFSET ${offsetIndex}`,
      values,
    ),
    database.query(`SELECT COUNT(*)::INTEGER AS count FROM place_reviews r ${where}`, placeId ? [placeId] : []),
  ])
  return { data: reviews.rows, pagination: { ...paging, total: total.rows[0].count } }
}

export async function createPlaceReview({ userId, placeId, rating, content, imageUrl = '' }) {
  const result = await database.query(
    `INSERT INTO place_reviews (id, user_id, place_id, rating, content, image_url)
     VALUES ($1, $2, $3, $4, $5, $6)
     RETURNING id, place_id, rating, content, image_url, created_at, updated_at`,
    [randomUUID(), userId, placeId, rating, content, imageUrl],
  )
  return result.rows[0]
}

export async function deletePlaceReview({ reviewId, userId }) {
  const found = await database.query('SELECT user_id FROM place_reviews WHERE id = $1', [reviewId])
  if (!found.rowCount) { const error = new Error('REVIEW_NOT_FOUND'); error.code = 'REVIEW_NOT_FOUND'; throw error }
  if (found.rows[0].user_id !== userId) { const error = new Error('REVIEW_FORBIDDEN'); error.code = 'REVIEW_FORBIDDEN'; throw error }
  await database.query('DELETE FROM place_reviews WHERE id = $1', [reviewId])
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
    `SELECT id, name, username, provider, profile_image
     FROM users WHERE id <> $1 ORDER BY created_at DESC`,
    [userId],
  )
  return result.rows.map((row) => ({ id: row.id, name: row.name, username: row.username, provider: row.provider, profileImage: row.profile_image || '' }))
}

export async function listFriends(userId) {
  const result = await database.query(
    `SELECT u.id, u.name, u.username, u.provider, u.profile_image,
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
  return result.rows.map((row) => ({ id: row.id, name: row.name, username: row.username, provider: row.provider, profileImage: row.profile_image || '', relationships: row.relationships || [] }))
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

export async function runMigrations() {
  const directory = join(dirname(fileURLToPath(import.meta.url)), '..', 'database', 'migrations')
  await database.query(`CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`)
  const files = (await readdir(directory)).filter((file) => file.endsWith('.sql')).sort()
  for (const file of files) {
    const applied = await database.query('SELECT 1 FROM schema_migrations WHERE name = $1', [file])
    if (applied.rowCount) continue
    const client = await database.connect()
    try {
      await client.query('BEGIN')
      await client.query(await readFile(join(directory, file), 'utf8'))
      await client.query('INSERT INTO schema_migrations (name) VALUES ($1)', [file])
      await client.query('COMMIT')
    } catch (error) { await client.query('ROLLBACK'); throw error } finally { client.release() }
  }
}

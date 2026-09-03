import { createServer } from 'node:http'
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import { extname, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { addFriend, authenticatePasswordUser, changePassword, createPasswordUser, createPlaceReview, createRelationshipRequest, createTrip, deleteFavorite, deletePlaceReview, deleteTrip, deleteUser, ensureConfiguredAdmin, getPlaceReviewSummaries, getPublicTrip, getTrip, initializeDatabase, isAdminUser, listCourses, listFavorites, listFriends, listNotifications, listOtherUsers, listReviews, listUsers, respondToRelationshipRequest, searchSeoulAreas, siteId, updateTrip, updateUserProfile, upsertFavorite, upsertGoogleUser } from './database.mjs'
import { createGoogleAuthorizationUrl, fetchGoogleProfile } from './oauth.mjs'
import { allowedOrigin, allowedOrigins, createRateLimiter, requestIp } from './security.mjs'

const staticRoot = resolve(fileURLToPath(new URL('../dist/', import.meta.url)))
const contentTypes = {
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.ico': 'image/x-icon',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.webp': 'image/webp',
}
const searchableCategories = new Set(['food', 'cafe', 'tour', 'photo', 'lodging', 'activity'])
const configuredPort = Number(process.env.PORT || 3001)
const port = Number.isInteger(configuredPort) && configuredPort > 0 ? configuredPort : 3001
const frontendUrl = (process.env.FRONTEND_URL?.trim() || 'http://localhost:5173').replace(/\/$/, '')
const kakaoRestApiKey = process.env.KAKAO_REST_API_KEY?.trim() || ''
const kakaoMobilityRestApiKey = process.env.KAKAO_MOBILITY_REST_API_KEY?.trim() || ''
const cacheTtlMs = 3 * 60 * 1000
const placesCache = new Map()
const routesCache = new Map()
const placesCacheMaxEntries = 250
const routesCacheMaxEntries = 100
// Keep tokens valid across server restarts when a deployment has not yet set a
// dedicated secret. DATABASE_URL is required and remains server-only; production
// deployments should still provide AUTH_TOKEN_SECRET explicitly.
const authSecret = process.env.AUTH_TOKEN_SECRET || createHash('sha256').update(process.env.DATABASE_URL || '').digest('base64url')
// Keep the production frontend available even if the hosting environment has
// not yet populated FRONTEND_URL. Additional origins remain opt-in through the
// comma-separated FRONTEND_URL setting.
const corsOrigins = allowedOrigins({ frontendUrl: process.env.FRONTEND_URL || 'https://where-silk.vercel.app' })
const rateLimiter = createRateLimiter()
const kakaoCategoryCodes = { food: 'FD6', cafe: 'CE7', tour: 'AT4', photo: 'AT4', activity: 'CT1', lodging: 'AD5' }
const kakaoCategoryKeywords = { food: '맛집', cafe: '카페', tour: '관광명소', photo: '사진 명소', activity: '놀거리', lodging: '숙소' }
const livePlaceMeta = {
  food: { tags: ['foodie'], groupFit: ['friends', 'couple', 'family', 'alone'] },
  cafe: { tags: ['cafe', 'rest'], groupFit: ['friends', 'couple', 'alone'] },
  tour: { tags: ['nature', 'photo', 'rest'], groupFit: ['friends', 'couple', 'family', 'alone'] },
  photo: { tags: ['photo'], groupFit: ['friends', 'couple', 'alone'] },
  activity: { tags: ['activity', 'shopping'], groupFit: ['friends', 'couple', 'family'] },
  lodging: { tags: ['rest'], groupFit: ['friends', 'couple', 'family', 'alone'] },
}
const preferenceSearches = {
  cafe: { category: 'cafe', categoryCode: 'CE7', tags: ['cafe', 'rest'] },
  foodie: { category: 'food', categoryCode: 'FD6', tags: ['foodie'] },
  photo: { category: 'photo', keyword: '사진 명소', tags: ['photo'] },
  nature: { category: 'tour', keyword: '공원', tags: ['nature', 'photo', 'rest'] },
  activity: { category: 'activity', categoryCode: 'CT1', tags: ['activity'] },
  shopping: { category: 'activity', keyword: '쇼핑몰', tags: ['shopping'] },
  rest: { category: 'tour', keyword: '산책로', tags: ['rest', 'nature'] },
  lodging: { category: 'lodging', categoryCode: 'AD5', tags: ['rest'] },
}
const seoulDistrictCenters = {
  강남구: [37.5172, 127.0473], 강동구: [37.5301, 127.1238], 강북구: [37.6396, 127.0257], 강서구: [37.5509, 126.8495], 관악구: [37.4784, 126.9516], 광진구: [37.5385, 127.0823], 구로구: [37.4954, 126.8874], 금천구: [37.4569, 126.8955], 노원구: [37.6542, 127.0568], 도봉구: [37.6688, 127.0471], 동대문구: [37.5744, 127.0396], 동작구: [37.5124, 126.9393], 마포구: [37.5663, 126.9019], 서대문구: [37.5791, 126.9368], 서초구: [37.4837, 127.0324], 성동구: [37.5633, 127.0371], 성북구: [37.5894, 127.0167], 송파구: [37.5145, 127.1059], 양천구: [37.5170, 126.8664], 영등포구: [37.5264, 126.8962], 용산구: [37.5326, 126.9906], 은평구: [37.6027, 126.9291], 종로구: [37.5735, 126.9788], 중구: [37.5641, 126.9979], 중랑구: [37.6063, 127.0927],
}
const seoulDistrictNames = new Set(Object.keys(seoulDistrictCenters))

function sendJson(response, status, body) {
  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  }
  if (response.corsOrigin) { headers['Access-Control-Allow-Origin'] = response.corsOrigin; headers.Vary = 'Origin' }
  response.writeHead(status, headers)
  response.end(JSON.stringify(body))
}

function isRateLimited(request, url) {
  const routes = [
    [request.method === 'POST' && url.pathname === '/api/auth/login', 5, 15 * 60_000],
    [request.method === 'POST' && url.pathname === '/api/auth/signup', 5, 60 * 60_000],
    [request.method === 'POST' && /^\/api\/places\/[^/]+\/reviews$/.test(url.pathname), 10, 60_000],
    [request.method === 'POST' && url.pathname === '/api/favorites', 40, 60_000],
    [request.method === 'POST' && url.pathname === '/api/trips', 20, 60_000],
  ]
  const route = routes.find(([matches]) => matches)
  if (!route) return null
  const [, limit, windowMs] = route
  return rateLimiter({ key: `${requestIp(request)}:${request.method}:${url.pathname.replace(/\/[^/]+$/, '')}`, limit, windowMs })
}

function redirect(response, location, cookies = []) {
  const headers = { Location: location }
  if (cookies.length) headers['Set-Cookie'] = cookies
  response.writeHead(302, headers)
  response.end()
}

function requestOrigin(request) {
  if (process.env.API_BASE_URL?.trim()) return process.env.API_BASE_URL.trim().replace(/\/$/, '')
  const forwardedProtocol = request.headers['x-forwarded-proto']
  const protocol = typeof forwardedProtocol === 'string' ? forwardedProtocol.split(',')[0] : 'http'
  return `${protocol}://${request.headers.host || `localhost:${port}`}`
}

function oauthCallbackUri(request) {
  return `${requestOrigin(request)}/api/auth/oauth/google/callback`
}

function parseCookies(request) {
  return Object.fromEntries((request.headers.cookie || '').split(';').filter(Boolean).map((item) => {
    const [key, ...value] = item.trim().split('=')
    return [key, decodeURIComponent(value.join('='))]
  }))
}

function oauthStateCookie(value, request, maxAge = 600) {
  const secure = requestOrigin(request).startsWith('https://') ? '; Secure' : ''
  return `where_oauth_state=${encodeURIComponent(value)}; Max-Age=${maxAge}; Path=/api/auth/oauth/google/callback; HttpOnly; SameSite=Lax${secure}`
}

function frontendOAuthRedirect(response, { user, token, error }, cookies = []) {
  const fragment = user
    ? `oauth_user=${Buffer.from(JSON.stringify(user)).toString('base64url')}&oauth_token=${encodeURIComponent(token || '')}`
    : `oauth_error=${encodeURIComponent(error || '소셜 로그인을 완료하지 못했습니다.')}`
  redirect(response, `${frontendUrl}/#${fragment}`, cookies)
}

async function startGoogleOAuth(request, response) {
  try {
    const state = randomBytes(32).toString('base64url')
    const location = createGoogleAuthorizationUrl({
      redirectUri: oauthCallbackUri(request),
      state,
    })
    redirect(response, location, [oauthStateCookie(state, request)])
  } catch (error) {
    const message = error instanceof Error && error.message === 'OAUTH_PROVIDER_NOT_CONFIGURED'
      ? 'Google 로그인 키가 설정되지 않았습니다.'
      : '소셜 로그인을 시작하지 못했습니다.'
    frontendOAuthRedirect(response, { error: message })
  }
}

async function completeGoogleOAuth(request, response, url) {
  const clearedCookie = oauthStateCookie('', request, 0)
  try {
    if (url.searchParams.has('error')) throw new Error('OAUTH_ACCESS_DENIED')
    const code = url.searchParams.get('code')
    const state = url.searchParams.get('state')
    const savedState = parseCookies(request).where_oauth_state
    if (!code || !state || !savedState || state !== savedState) throw new Error('OAUTH_STATE_INVALID')

    const profile = await fetchGoogleProfile(code, oauthCallbackUri(request))
    const user = await upsertGoogleUser(profile)
    frontendOAuthRedirect(response, { user, token: createAuthToken(user.id) }, [clearedCookie])
  } catch (error) {
    console.error('Google OAuth callback failed:', error instanceof Error ? error.message : 'UNKNOWN_ERROR')
    const message = error instanceof Error && error.message === 'OAUTH_ACCESS_DENIED'
      ? '로그인 동의가 취소됐습니다.'
      : '소셜 로그인을 완료하지 못했습니다.'
    frontendOAuthRedirect(response, { error: message }, [clearedCookie])
  }
}

function fromCache(cache, key) {
  const hit = cache.get(key)
  if (!hit || hit.expiresAt <= Date.now()) {
    cache.delete(key)
    return null
  }
  // Refresh its insertion order so the Map behaves as a small LRU cache.
  cache.delete(key)
  cache.set(key, hit)
  return hit.value
}

function cacheValue(cache, key, value, maxEntries) {
  const now = Date.now()
  for (const [cachedKey, entry] of cache) {
    if (entry.expiresAt <= now) cache.delete(cachedKey)
  }
  while (cache.size >= maxEntries) cache.delete(cache.keys().next().value)
  cache.set(key, { value, expiresAt: Date.now() + cacheTtlMs })
  return value
}

function haversineKm(lat1, lng1, lat2, lng2) {
  const radians = (value) => value * Math.PI / 180
  const a = Math.sin(radians(lat2 - lat1) / 2) ** 2 + Math.cos(radians(lat1)) * Math.cos(radians(lat2)) * Math.sin(radians(lng2 - lng1) / 2) ** 2
  return 6371 * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a))
}

function estimatedPrice(category, id) {
  const hash = [...String(id)].reduce((value, character) => ((value * 31) + character.charCodeAt(0)) >>> 0, 0)
  const ranges = { food: [12_000, 38_000], cafe: [4_500, 13_000], tour: [0, 9_000], photo: [0, 12_000], activity: [8_000, 45_000], lodging: [90_000, 220_000] }
  const [minimum, maximum] = ranges[category] || [0, 10_000]
  return Math.round((minimum + ((hash % 1000) / 1000) * (maximum - minimum)) / 1000) * 1000
}

function createAuthToken(userId) {
  const payload = Buffer.from(JSON.stringify({ sub: userId, exp: Date.now() + 1000 * 60 * 60 * 24 * 14 })).toString('base64url')
  const signature = createHmac('sha256', authSecret).update(payload).digest('base64url')
  return `${payload}.${signature}`
}

function authenticatedUserId(request) {
  const token = request.headers.authorization?.replace(/^Bearer\s+/i, '')
  if (!token || !token.includes('.')) return null
  const [payload, signature] = token.split('.')
  const expected = createHmac('sha256', authSecret).update(payload).digest('base64url')
  if (signature.length !== expected.length || !timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null
  try { const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')); return data.exp > Date.now() && typeof data.sub === 'string' ? data.sub : null } catch { return null }
}

function favoriteInput(input) {
  const placeId = typeof input?.placeId === 'string' ? input.placeId.trim() : ''
  const placeName = typeof input?.placeName === 'string' ? input.placeName.trim() : ''
  if (!placeId || placeId.length > 255 || !placeName || placeName.length > 255) return { error: '장소 정보를 확인해 주세요.' }
  const numberOrNull = (value) => Number.isFinite(Number(value)) ? Number(value) : null
  const latitude = numberOrNull(input.latitude)
  const longitude = numberOrNull(input.longitude)
  if ((latitude !== null && (latitude < -90 || latitude > 90)) || (longitude !== null && (longitude < -180 || longitude > 180))) return { error: '장소 좌표를 확인해 주세요.' }
  return {
    value: {
      placeId,
      placeName,
      address: typeof input.address === 'string' ? input.address.slice(0, 2_000) : '',
      category: typeof input.category === 'string' ? input.category.slice(0, 100) : 'tour',
      imageUrl: typeof input.imageUrl === 'string' ? input.imageUrl.slice(0, 4_000) : '',
      latitude,
      longitude,
      placeData: input.place && typeof input.place === 'object' && !Array.isArray(input.place) ? input.place : {},
    },
  }
}

async function kakaoFetch(url, options, attempts = 2) {
  let lastError
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      const response = await fetch(url, { ...options, signal: AbortSignal.timeout(10_000) })
      if (response.ok || (response.status < 500 && response.status !== 429)) return response
      lastError = new Error(`KAKAO_${response.status}`)
    } catch (error) { lastError = error }
    if (attempt + 1 < attempts) await new Promise((resolve) => setTimeout(resolve, 250))
  }
  throw lastError || new Error('KAKAO_UNAVAILABLE')
}

function tripInput(input) {
  const text = (value, max = 255) => typeof value === 'string' ? value.trim().slice(0, max) : ''
  const integer = (value, fallback = 0) => Number.isFinite(Number(value)) ? Math.max(0, Math.floor(Number(value))) : fallback
  const coordinate = (value, min, max) => Number.isFinite(Number(value)) && Number(value) >= min && Number(value) <= max ? Number(value) : null
  const title = text(input?.title, 120)
  const stops = Array.isArray(input?.stops) ? input.stops : []
  if (!title || stops.length === 0 || stops.length > 60) return { error: '코스 제목과 장소 목록을 확인해주세요.' }
  const normalizedStops = []
  for (const stop of stops) {
    const placeName = text(stop?.placeName, 255)
    const latitude = coordinate(stop?.latitude, -90, 90)
    const longitude = coordinate(stop?.longitude, -180, 180)
    if (!placeName || latitude === null || longitude === null) return { error: '코스 장소 정보를 확인해주세요.' }
    normalizedStops.push({
      placeId: text(stop.placeId, 255), placeName, category: text(stop.category, 100) || 'tour', area: text(stop.area, 2_000),
      latitude, longitude, estimatedCost: integer(stop.estimatedCost), durationMin: integer(stop.durationMin),
      metadata: stop.metadata && typeof stop.metadata === 'object' && !Array.isArray(stop.metadata) ? stop.metadata : {},
    })
  }
  const companion = ['friends', 'couple', 'family', 'alone'].includes(input?.companion) ? input.companion : 'alone'
  const transport = ['public', 'car'].includes(input?.transport) ? input.transport : 'public'
  const weather = ['sunny', 'cloudy', 'rain'].includes(input?.weather) ? input.weather : 'sunny'
  const list = (value) => Array.isArray(value) ? value.filter((item) => typeof item === 'string').slice(0, 30) : []
  return { value: {
    title, description: text(input?.description, 4_000), startArea: text(input?.startArea, 255),
    dateStart: /^\d{4}-\d{2}-\d{2}$/.test(input?.dateStart || '') ? input.dateStart : null,
    dateEnd: /^\d{4}-\d{2}-\d{2}$/.test(input?.dateEnd || '') ? input.dateEnd : null,
    companion, headcount: Math.min(100, Math.max(1, integer(input?.headcount, 1))), budgetPerPerson: integer(input?.budgetPerPerson),
    transport, weather, likes: list(input?.likes), dislikes: list(input?.dislikes),
    routeCoordinates: Array.isArray(input?.routeCoordinates) ? input.routeCoordinates.slice(0, 100) : [],
    isPublic: input?.isPublic === true, stops: normalizedStops,
  } }
}

function kakaoPlaceToPlace(item, category, origin, tags) {
  const lat = Number(item.y); const lng = Number(item.x)
  const distanceKm = Number(haversineKm(origin.lat, origin.lng, lat, lng).toFixed(2))
  const metadata = livePlaceMeta[category] || livePlaceMeta.tour
  const price = estimatedPrice(category, item.id)
  const lodging = category === 'lodging' ? { pricePerNight: price, capacity: 2, parking: true, bed: '더블 또는 트윈' } : undefined
  return { id: `kakao-${item.id}`, name: item.place_name, area: item.road_address_name || item.address_name || '서울', category: category || 'tour', lat, lng, tags: tags || metadata.tags, groupFit: metadata.groupFit, indoor: category !== 'tour' && category !== 'photo', price, durationMin: category === 'food' ? 70 : 60, rating: 0, description: item.category_name || item.place_name, image: '', accent: '#1d9b77', distanceKm, phone: item.phone || '', placeUrl: item.place_url || '', lodging }
}

function searchBounds(url) {
  const south = Number(url.searchParams.get('south'))
  const north = Number(url.searchParams.get('north'))
  const west = Number(url.searchParams.get('west'))
  const east = Number(url.searchParams.get('east'))
  return Number.isFinite(south) && Number.isFinite(north) && Number.isFinite(west) && Number.isFinite(east)
    && south < north && west < east
    ? { south, north, west, east }
    : null
}

function isInBounds(place, bounds) {
  return !bounds || (place.lat >= bounds.south && place.lat <= bounds.north && place.lng >= bounds.west && place.lng <= bounds.east)
}

function requestedSearchProfiles(category, tags, includeLodging) {
  if (category) {
    const profile = Object.values(preferenceSearches).find((item) => item.category === category)
    return profile ? [profile] : []
  }
  const selected = tags.map((tag) => preferenceSearches[tag]).filter(Boolean)
  const unique = [...new Map(selected.map((profile) => [`${profile.category}:${profile.keyword || profile.categoryCode}`, profile])).values()]
  if (includeLodging && !unique.some((profile) => profile.category === 'lodging')) unique.push(preferenceSearches.lodging)
  // Accommodation is a separate result type. It must never appear in the
  // ordinary explore list unless a caller explicitly asks for it.
  return unique.length ? unique : [...searchableCategories].filter((item) => item !== 'lodging').map((item) => ({ category: item, categoryCode: kakaoCategoryCodes[item], tags: livePlaceMeta[item]?.tags || [] }))
}

async function searchKakaoPlaces(url, category, keyword, area, companion, limit, page, origin, bounds, tags, includeLodging) {
  if (!kakaoRestApiKey) throw new Error('KAKAO_PLACES_NOT_CONFIGURED')
  const selectedDistrict = seoulDistrictNames.has(area)
  const searchKeyword = keyword
  const districtCenter = selectedDistrict ? seoulDistrictCenters[area] : null
  const searchCenter = districtCenter ? { lat: districtCenter[0], lng: districtCenter[1] } : origin
  // "전체"는 동행 유형으로 좁히지 않고, 모든 화면 카테고리를 함께 검색한다.
  // 각 카카오 응답에 카테고리를 보존해야 지도 핀도 맛집·카페·관광지·숙소·액티비티 아이콘으로 구분된다.
  const profiles = requestedSearchProfiles(category, tags, includeLodging)
  const perCategoryLimit = Math.min(15, Math.max(3, Math.ceil(limit / profiles.length) + 3))
  const radius = String(Math.min(Number(url.searchParams.get('radius') || 8000), 20000))
  const headers = { Authorization: `KakaoAK ${kakaoRestApiKey}` }
  const requestDocuments = async (profile, query) => {
    const endpoint = query ? 'https://dapi.kakao.com/v2/local/search/keyword.json' : 'https://dapi.kakao.com/v2/local/search/category.json'
    const params = new URLSearchParams({ size: String(perCategoryLimit), page: String(page), x: String(searchCenter.lng), y: String(searchCenter.lat), radius, ...(query ? { query } : { category_group_code: profile.categoryCode || kakaoCategoryCodes[profile.category] }) })
    const response = await kakaoFetch(`${endpoint}?${params}`, { headers })
    if (!response.ok) throw new Error(`KAKAO_PLACES_${response.status}`)
    const payload = await response.json()
    return { documents: payload.documents || [], isEnd: Boolean(payload.meta?.is_end) }
  }
  const responses = await Promise.all(profiles.map(async (profile) => {
    try {
      const query = searchKeyword || profile.keyword ? `${area || '서울'} ${searchKeyword || profile.keyword}` : ''
      let { documents, isEnd } = await requestDocuments(profile, query)
      if (selectedDistrict) documents = documents.filter((item) => `${item.address_name || ''} ${item.road_address_name || ''}`.includes(area))
      // A category response can use a shortened address and be filtered out even
      // though Kakao has results in the selected district. Retry that one profile
      // with an explicit district keyword before treating it as an empty result.
      if (selectedDistrict && documents.length === 0 && !query) {
        const fallback = await requestDocuments(profile, `${area} ${kakaoCategoryKeywords[profile.category] || profile.category}`)
        documents = fallback.documents.filter((item) => `${item.address_name || ''} ${item.road_address_name || ''}`.includes(area))
        isEnd = fallback.isEnd
      }
      return { places: documents.map((item) => kakaoPlaceToPlace(item, profile.category, origin, profile.tags)), isEnd, failed: false }
    } catch (error) {
      console.warn('Kakao category search failed:', profile.category, error instanceof Error ? error.message : 'UNKNOWN_ERROR')
      // One failed Kakao category must not hide successful results from the others.
      return { places: [], isEnd: true, failed: true }
    }
  }))
  if (responses.every((response) => response.failed)) throw new Error('KAKAO_PLACES_UNAVAILABLE')
  const data = [...new Map(responses.flatMap((response) => response.places).map((place) => [place.id, place])).values()]
    .filter((place) => isInBounds(place, bounds))
    .sort((a, b) => a.distanceKm - b.distanceKm)
    .slice(0, limit)
  return { data, meta: { total: data.length, area: area || '서울', category: category || 'all', source: 'kakao', page, hasMore: responses.some((response) => !response.isEnd) } }
}

async function findPlaces(url) {
  const area = url.searchParams.get('area')?.trim() ?? ''
  const category = url.searchParams.get('category')?.trim() ?? ''
  const companion = url.searchParams.get('companion')?.trim() ?? ''
  const keyword = url.searchParams.get('q')?.trim().toLowerCase() ?? ''
  const tags = (url.searchParams.get('tags') || '').split(',').map((tag) => tag.trim()).filter((tag) => Object.hasOwn(preferenceSearches, tag))
  const includeLodging = url.searchParams.get('includeLodging') === 'true'
  const requestedLimit = Number(url.searchParams.get('limit') ?? 24)
  const limit = Number.isFinite(requestedLimit) ? Math.max(1, Math.min(requestedLimit, 40)) : 24
  const requestedPage = Number(url.searchParams.get('page') ?? 1)
  const page = Number.isFinite(requestedPage) ? Math.max(1, Math.min(Math.floor(requestedPage), 45)) : 1

  if (category && !searchableCategories.has(category)) {
    return { error: 'category must be food, cafe, tour, photo, lodging, or activity' }
  }
  if (!seoulDistrictNames.has(area)) {
    return { error: 'area must be one of Seoul\'s 25 districts' }
  }

  const origin = { lat: Number(url.searchParams.get('lat')) || 37.5668, lng: Number(url.searchParams.get('lng')) || 126.978 }
  const bounds = searchBounds(url)
  const cacheKey = JSON.stringify({ area, category, companion, keyword, tags, includeLodging, limit, page, lat: origin.lat.toFixed(4), lng: origin.lng.toFixed(4), radius: url.searchParams.get('radius') || '', bounds, zoom: url.searchParams.get('zoom') || '' })
  const cached = fromCache(placesCache, cacheKey)
  try {
    const result = cached || cacheValue(placesCache, cacheKey, await searchKakaoPlaces(url, category, keyword, area, companion, limit, page, origin, bounds, tags, includeLodging), placesCacheMaxEntries)
    const summaries = await getPlaceReviewSummaries(result.data.map((place) => place.id))
    const summaryByPlace = new Map(summaries.map((summary) => [summary.placeId, summary]))
    return { ...result, data: result.data.map((place) => ({ ...place, ...(summaryByPlace.get(place.id) || { rating: 0, reviewCount: 0 }) })) }
  } catch (error) {
    console.error('Kakao place search failed:', error instanceof Error ? error.message : 'UNKNOWN_ERROR')
    return { error: 'KAKAO_PLACES_UNAVAILABLE', status: 502 }
  }
}

function validPoint(value) {
  return value && Number.isFinite(value.lat) && Number.isFinite(value.lng)
    && value.lat >= -90 && value.lat <= 90 && value.lng >= -180 && value.lng <= 180
}

function routeCoordinates(payload) {
  const roads = payload.routes?.[0]?.sections?.flatMap((section) => section.roads || []) || []
  return roads.flatMap((road) => {
    const vertices = road.vertexes || []
    const points = []
    for (let index = 0; index < vertices.length; index += 2) points.push({ lng: vertices[index], lat: vertices[index + 1] })
    return points
  })
}

async function findRoute(input) {
  const origin = input?.origin
  const stops = Array.isArray(input?.stops) ? input.stops.slice(0, 5) : []
  if (!validPoint(origin) || stops.length === 0 || !stops.every(validPoint)) return { error: 'INVALID_ROUTE_POINTS', status: 400 }
  if (input.transport !== 'car') return { error: 'PUBLIC_TRANSIT_ROUTE_UNAVAILABLE', status: 422 }
  if (!kakaoMobilityRestApiKey) return { error: 'KAKAO_MOBILITY_NOT_CONFIGURED', status: 503 }

  const cacheKey = JSON.stringify({ origin, stops, transport: input.transport })
  const cached = fromCache(routesCache, cacheKey)
  if (cached) return cached
  const destination = stops.at(-1)
  const params = new URLSearchParams({
    origin: `${origin.lng},${origin.lat}`,
    destination: `${destination.lng},${destination.lat}`,
    priority: 'RECOMMEND',
    summary: 'false',
  })
  if (stops.length > 1) params.set('waypoints', stops.slice(0, -1).map((stop) => `${stop.lng},${stop.lat}`).join('|'))
  try {
    const response = await kakaoFetch(`https://apis-navi.kakaomobility.com/v1/directions?${params}`, {
      headers: { Authorization: `KakaoAK ${kakaoMobilityRestApiKey}` },
    })
    if (!response.ok) throw new Error(`KAKAO_ROUTE_${response.status}`)
    const payload = await response.json()
    const summary = payload.routes?.[0]?.summary
    const coordinates = routeCoordinates(payload)
    if (!summary || coordinates.length < 2) throw new Error('KAKAO_ROUTE_EMPTY')
    return cacheValue(routesCache, cacheKey, { data: { coordinates, distanceMeters: summary.distance, durationSeconds: summary.duration } }, routesCacheMaxEntries)
  } catch (error) {
    console.error('Kakao route search failed:', error instanceof Error ? error.message : 'UNKNOWN_ERROR')
    return { error: 'KAKAO_ROUTE_UNAVAILABLE', status: 502 }
  }
}

async function readJsonBody(request, maxBytes = 16_384) {
  const chunks = []
  let size = 0
  for await (const chunk of request) {
    size += chunk.length
    if (size > maxBytes) throw new Error('REQUEST_TOO_LARGE')
    chunks.push(chunk)
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'))
  } catch {
    throw new Error('INVALID_JSON')
  }
}

function validatePassword(password) {
  if (!/^(?=.*[A-Za-z])(?=.*\d).{8,128}$/.test(password)) return { error: 'Password must contain letters and numbers and be 8 to 128 characters long.' }
  return { value: password }
}

function validateSignup(input) {
  const name = typeof input.name === 'string' ? input.name.trim().normalize('NFC') : ''
  const username = typeof input.username === 'string' ? input.username.trim().toLowerCase() : ''
  const password = typeof input.password === 'string' ? input.password : ''
  if (name.length < 2 || name.length > 20) return { error: '닉네임은 2~20자로 입력해 주세요.' }
  if (!/^[a-zA-Z0-9_]{4,20}$/.test(username)) return { error: '아이디는 영문, 숫자, 밑줄 4~20자로 입력해 주세요.' }
  if (!/^(?=.*[A-Za-z])(?=.*\d).{8,128}$/.test(password)) return { error: '비밀번호는 영문과 숫자를 섞어 8~128자로 입력해 주세요.' }
  return { value: { name, username, password } }
}

function validateProfile(input) {
  const name = typeof input.name === 'string' ? input.name.trim().normalize('NFC') : ''
  const profileImage = typeof input.profileImage === 'string' ? input.profileImage : ''
  if (name.length < 2 || name.length > 20) return { error: 'Name must be 2 to 20 characters long.' }
  if (profileImage.length > 7_100_000) return { error: 'Profile image is too large.' }
  if (profileImage && !/^https:\/\/.+/.test(profileImage) && !/^data:image\/(?:jpeg|png);base64,[A-Za-z0-9+/]+={0,2}$/.test(profileImage)) {
    return { error: 'Profile image must be a JPG or PNG image.' }
  }
  return { value: { name, profileImage } }
}

async function serveStatic(url, response) {
  const requestedPath = decodeURIComponent(url.pathname)
  const relativePath = requestedPath === '/' ? '/index.html' : requestedPath
  const candidate = resolve(staticRoot, `.${relativePath}`)
  if (candidate !== staticRoot && !candidate.startsWith(`${staticRoot}${sep}`)) return false

  let filePath = candidate
  try {
    await readFile(filePath)
  } catch {
    if (extname(relativePath)) return false
    filePath = resolve(staticRoot, 'index.html')
  }

  const body = await readFile(filePath)
  response.writeHead(200, {
    'Cache-Control': extname(filePath) === '.html' ? 'no-cache' : 'public, max-age=31536000, immutable',
    'Content-Type': contentTypes[extname(filePath)] || 'application/octet-stream',
  })
  response.end(body)
  return true
}

let databaseReady = false
let databaseError = ''

// Render must be able to bind its assigned port even while PostgreSQL is
// temporarily unavailable. Retry DB initialization in the background instead
// of terminating the web process.
function initializeDatabaseInBackground() {
  void (async () => {
    try {
      await initializeDatabase()
      await ensureConfiguredAdmin()
      databaseReady = true
      databaseError = ''
      console.log('Database initialization complete.')
    } catch (error) {
      databaseError = error instanceof Error ? error.message : 'DATABASE_UNAVAILABLE'
      console.error('Database initialization failed:', databaseError)
      setTimeout(initializeDatabaseInBackground, 30_000)
    }
  })()
}

initializeDatabaseInBackground()

const server = createServer((request, response) => {
  void handleRequest(request, response).catch((error) => {
    console.error('Unhandled request error:', error instanceof Error ? error.message : 'UNKNOWN_ERROR')
    if (!response.headersSent) sendJson(response, 503, { error: 'SERVICE_TEMPORARILY_UNAVAILABLE' })
    else response.end()
  })
})

async function handleRequest(request, response) {
  const url = new URL(request.url ?? '/', 'http://localhost:3001')
  const origin = typeof request.headers.origin === 'string' ? request.headers.origin : ''
  response.corsOrigin = allowedOrigin(origin, corsOrigins)
  if (origin && !response.corsOrigin) return sendJson(response, 403, { error: 'CORS_ORIGIN_NOT_ALLOWED' })
  if (request.method === 'OPTIONS') return sendJson(response, 204, {})
  const rate = isRateLimited(request, url)
  if (rate && !rate.allowed) {
    response.setHeader('Retry-After', String(rate.retryAfterSeconds))
    return sendJson(response, 429, { error: 'RATE_LIMITED', retryAfterSeconds: rate.retryAfterSeconds })
  }
  if (request.method === 'GET' && url.pathname === '/api/health') return sendJson(response, 200, { ok: true, database: databaseReady ? 'postgresql' : 'unavailable', siteId, ...(databaseError ? { databaseError: 'DATABASE_UNAVAILABLE' } : {}) })
  if (request.method === 'GET' && url.pathname === '/api/areas') {
    const query = url.searchParams.get('q') || ''
    const limit = url.searchParams.get('limit') || '8'
    return sendJson(response, 200, { data: await searchSeoulAreas(query, limit) })
  }
  if (request.method === 'GET' && url.pathname === '/api/courses') {
    const userId = authenticatedUserId(request)
    if (!userId) return sendJson(response, 401, { error: '로그인이 필요합니다.' })
    const result = await listCourses({ userId, page: url.searchParams.get('page'), limit: url.searchParams.get('limit') })
    return sendJson(response, 200, { ...result, pagination: { ...result.pagination, totalPages: Math.ceil(result.pagination.total / result.pagination.limit) } })
  }
  if (request.method === 'GET' && /^\/api\/share\/trips\/[^/]+$/.test(url.pathname)) {
    const shareToken = decodeURIComponent(url.pathname.split('/').at(-1) || '').trim()
    const trip = shareToken ? await getPublicTrip(shareToken) : null
    return trip ? sendJson(response, 200, { data: trip }) : sendJson(response, 404, { error: '공개 코스를 찾을 수 없습니다.' })
  }
  if (request.method === 'GET' && url.pathname === '/api/trips') {
    const userId = authenticatedUserId(request)
    if (!userId) return sendJson(response, 401, { error: '로그인이 필요합니다.' })
    const result = await listCourses({ userId, page: url.searchParams.get('page'), limit: url.searchParams.get('limit') })
    return sendJson(response, 200, { ...result, pagination: { ...result.pagination, totalPages: Math.ceil(result.pagination.total / result.pagination.limit) } })
  }
  if (request.method === 'POST' && url.pathname === '/api/trips') {
    const userId = authenticatedUserId(request)
    if (!userId) return sendJson(response, 401, { error: '로그인이 필요합니다.' })
    try {
      const validation = tripInput(await readJsonBody(request, 250_000))
      if ('error' in validation) return sendJson(response, 400, validation)
      return sendJson(response, 201, { data: await createTrip({ userId, input: validation.value }) })
    } catch (error) { return sendJson(response, error instanceof Error && error.message === 'REQUEST_TOO_LARGE' ? 413 : 400, { error: '코스를 저장하지 못했습니다.' }) }
  }
  if (request.method === 'GET' && /^\/api\/trips\/[^/]+$/.test(url.pathname)) {
    const userId = authenticatedUserId(request)
    if (!userId) return sendJson(response, 401, { error: '로그인이 필요합니다.' })
    const trip = await getTrip({ userId, tripId: decodeURIComponent(url.pathname.split('/').at(-1) || '') })
    return trip ? sendJson(response, 200, { data: trip }) : sendJson(response, 404, { error: '코스를 찾을 수 없습니다.' })
  }
  if (request.method === 'PUT' && /^\/api\/trips\/[^/]+$/.test(url.pathname)) {
    const userId = authenticatedUserId(request)
    if (!userId) return sendJson(response, 401, { error: '로그인이 필요합니다.' })
    try {
      const validation = tripInput(await readJsonBody(request, 250_000))
      if ('error' in validation) return sendJson(response, 400, validation)
      const data = await updateTrip({ userId, tripId: decodeURIComponent(url.pathname.split('/').at(-1) || ''), input: validation.value })
      return sendJson(response, 200, { data })
    } catch (error) { return sendJson(response, error?.code === 'TRIP_NOT_FOUND' ? 404 : error instanceof Error && error.message === 'REQUEST_TOO_LARGE' ? 413 : 400, { error: '코스를 수정하지 못했습니다.' }) }
  }
  if (request.method === 'DELETE' && /^\/api\/trips\/[^/]+$/.test(url.pathname)) {
    const userId = authenticatedUserId(request)
    if (!userId) return sendJson(response, 401, { error: '로그인이 필요합니다.' })
    const deleted = await deleteTrip({ userId, tripId: decodeURIComponent(url.pathname.split('/').at(-1) || '') })
    return deleted ? sendJson(response, 200, { ok: true }) : sendJson(response, 404, { error: '코스를 찾을 수 없습니다.' })
  }
  if (request.method === 'GET' && url.pathname === '/api/favorites') {
    const userId = authenticatedUserId(request)
    if (!userId) return sendJson(response, 401, { error: '로그인이 필요합니다.' })
    return sendJson(response, 200, { data: await listFavorites(userId) })
  }
  if (request.method === 'POST' && url.pathname === '/api/favorites') {
    const userId = authenticatedUserId(request)
    if (!userId) return sendJson(response, 401, { error: '로그인이 필요합니다.' })
    try {
      const validation = favoriteInput(await readJsonBody(request, 32_768))
      if ('error' in validation) return sendJson(response, 400, validation)
      return sendJson(response, 201, { data: await upsertFavorite({ userId, ...validation.value }) })
    } catch (error) {
      return sendJson(response, error instanceof Error && error.message === 'REQUEST_TOO_LARGE' ? 413 : 400, { error: '찜한 장소를 저장하지 못했습니다.' })
    }
  }
  if (request.method === 'DELETE' && /^\/api\/favorites\/[^/]+$/.test(url.pathname)) {
    const userId = authenticatedUserId(request)
    if (!userId) return sendJson(response, 401, { error: '로그인이 필요합니다.' })
    const placeId = decodeURIComponent(url.pathname.split('/').at(-1) || '').trim()
    if (!placeId) return sendJson(response, 400, { error: '장소 정보를 확인해 주세요.' })
    return await deleteFavorite({ userId, placeId })
      ? sendJson(response, 200, { ok: true })
      : sendJson(response, 404, { error: '찜한 장소를 찾을 수 없습니다.' })
  }
  if (request.method === 'GET' && url.pathname === '/api/reviews') {
    const result = await listReviews({ placeId: url.searchParams.get('placeId') || '', page: url.searchParams.get('page'), limit: url.searchParams.get('limit') })
    return sendJson(response, 200, { ...result, pagination: { ...result.pagination, totalPages: Math.ceil(result.pagination.total / result.pagination.limit) } })
  }
  if (request.method === 'GET' && /^\/api\/places\/[^/]+\/reviews$/.test(url.pathname)) {
    const placeId = decodeURIComponent(url.pathname.split('/')[3])
    const result = await listReviews({ placeId, page: url.searchParams.get('page'), limit: url.searchParams.get('limit') })
    return sendJson(response, 200, result)
  }
  if (request.method === 'POST' && /^\/api\/places\/[^/]+\/reviews$/.test(url.pathname)) {
    const userId = authenticatedUserId(request)
    if (!userId) return sendJson(response, 401, { error: '로그인이 필요합니다.' })
    try {
      // Client images are compressed before upload; keep payloads bounded.
      const input = await readJsonBody(request, 800_000)
      const content = typeof input.content === 'string' ? input.content.trim() : ''
      const rating = Number(input.rating)
      const imageUrl = typeof input.imageUrl === 'string' ? input.imageUrl : ''
      const validImage = !imageUrl || (/^data:image\/(jpeg|png|webp);base64,/i.test(imageUrl) && imageUrl.length <= 700_000)
      if (!content || content.length > 1000 || !Number.isInteger(rating) || rating < 1 || rating > 5) return sendJson(response, 400, { error: '후기 내용과 1~5점 별점을 확인해 주세요.' })
      if (!validImage) return sendJson(response, 400, { error: 'Review image must be a compressed JPEG, PNG, or WebP.' })
      const placeId = decodeURIComponent(url.pathname.split('/')[3])
      const review = await createPlaceReview({ userId, placeId, rating, content, imageUrl })
      const [summary] = await getPlaceReviewSummaries([placeId])
      return sendJson(response, 201, { data: { ...review, user_id: userId, summary: summary || { placeId, rating, reviewCount: 1 } } })
    } catch { return sendJson(response, 400, { error: '후기를 등록하지 못했습니다.' }) }
  }
  if (request.method === 'DELETE' && /^\/api\/reviews\/[^/]+$/.test(url.pathname)) {
    const userId = authenticatedUserId(request)
    if (!userId) return sendJson(response, 401, { error: '로그인이 필요합니다.' })
    try { await deletePlaceReview({ reviewId: url.pathname.split('/').at(-1), userId }); return sendJson(response, 200, { ok: true })
    } catch (error) { return sendJson(response, error?.code === 'REVIEW_FORBIDDEN' ? 403 : error?.code === 'REVIEW_NOT_FOUND' ? 404 : 500, { error: error?.code || 'REVIEW_DELETE_FAILED' }) }
  }
  if (request.method === 'GET' && url.pathname === '/api/auth/oauth/google') return startGoogleOAuth(request, response)
  if (request.method === 'GET' && url.pathname === '/api/auth/oauth/google/callback') return completeGoogleOAuth(request, response, url)
  if (request.method === 'GET' && url.pathname === '/api/social/users') {
    const userId = authenticatedUserId(request)
    if (!userId) return sendJson(response, 401, { error: '로그인이 필요합니다.' })
    return sendJson(response, 200, { data: await listOtherUsers(userId) })
  }
  if (request.method === 'GET' && url.pathname === '/api/admin/users') {
    const userId = authenticatedUserId(request)
    if (!userId) return sendJson(response, 401, { error: '로그인이 필요합니다.' })
    if (!(await isAdminUser(userId))) return sendJson(response, 403, { error: '관리자 권한이 필요합니다.' })
    return sendJson(response, 200, { data: await listUsers() })
  }
  if (request.method === 'DELETE' && /^\/api\/admin\/users\/[^/]+$/.test(url.pathname)) {
    const userId = authenticatedUserId(request)
    if (!userId) return sendJson(response, 401, { error: '로그인이 필요합니다.' })
    if (!(await isAdminUser(userId))) return sendJson(response, 403, { error: '관리자 권한이 필요합니다.' })
    const targetUserId = decodeURIComponent(url.pathname.split('/').at(-1) || '')
    if (!targetUserId) return sendJson(response, 400, { error: '사용자 정보를 확인해 주세요.' })
    if (targetUserId === userId) return sendJson(response, 400, { error: '관리자 계정은 여기서 삭제할 수 없습니다.' })
    return await deleteUser(targetUserId)
      ? sendJson(response, 200, { ok: true })
      : sendJson(response, 404, { error: '사용자를 찾을 수 없습니다.' })
  }
  if (request.method === 'GET' && url.pathname === '/api/social/friends') {
    const userId = authenticatedUserId(request)
    if (!userId) return sendJson(response, 401, { error: '로그인이 필요합니다.' })
    return sendJson(response, 200, { data: await listFriends(userId) })
  }
  if (request.method === 'GET' && url.pathname === '/api/social/notifications') {
    const userId = authenticatedUserId(request)
    if (!userId) return sendJson(response, 401, { error: '로그인이 필요합니다.' })
    return sendJson(response, 200, { data: await listNotifications(userId) })
  }
  if (request.method === 'POST' && url.pathname === '/api/social/friends') {
    const userId = authenticatedUserId(request)
    if (!userId) return sendJson(response, 401, { error: '로그인이 필요합니다.' })
    try {
      const { friendId } = await readJsonBody(request)
      if (typeof friendId !== 'string' || !friendId.trim()) return sendJson(response, 400, { error: 'friendId is required' })
      await addFriend(userId, friendId)
      return sendJson(response, 201, { ok: true })
    } catch (error) { return sendJson(response, 400, { error: error instanceof Error ? error.message : 'FRIEND_ADD_FAILED' }) }
  }
  if (request.method === 'POST' && url.pathname === '/api/social/relationship-requests') {
    const userId = authenticatedUserId(request)
    if (!userId) return sendJson(response, 401, { error: '로그인이 필요합니다.' })
    try {
      const { recipientId, relationshipType } = await readJsonBody(request)
      if (typeof recipientId !== 'string' || !recipientId.trim() || !['friend', 'couple', 'family'].includes(relationshipType)) return sendJson(response, 400, { error: 'invalid relationship request' })
      return sendJson(response, 201, { data: await createRelationshipRequest(userId, recipientId, relationshipType) })
    } catch (error) { return sendJson(response, 400, { error: error instanceof Error ? error.message : 'RELATIONSHIP_REQUEST_FAILED' }) }
  }
  if (request.method === 'POST' && /^\/api\/social\/notifications\/[^/]+\/respond$/.test(url.pathname)) {
    const userId = authenticatedUserId(request)
    if (!userId) return sendJson(response, 401, { error: '로그인이 필요합니다.' })
    try {
      const requestId = url.pathname.split('/')[4]
      const { accepted } = await readJsonBody(request)
      if (typeof accepted !== 'boolean') return sendJson(response, 400, { error: 'invalid notification response' })
      return sendJson(response, 200, { data: await respondToRelationshipRequest(userId, requestId, accepted) })
    } catch (error) { return sendJson(response, 400, { error: error instanceof Error ? error.message : 'NOTIFICATION_RESPONSE_FAILED' }) }
  }
  if (request.method === 'POST' && url.pathname === '/api/auth/signup') {
    try {
      const validation = validateSignup(await readJsonBody(request))
      if ('error' in validation) return sendJson(response, 400, validation)
      const user = await createPasswordUser(validation.value)
      return sendJson(response, 201, { user, token: createAuthToken(user.id) })
    } catch (error) {
      if (error instanceof Error && error.code === 'USERNAME_ALREADY_EXISTS') return sendJson(response, 409, { error: '이미 사용 중인 아이디입니다.' })
      if (error instanceof Error && error.message === 'INVALID_JSON') return sendJson(response, 400, { error: '요청 형식이 올바르지 않습니다.' })
      if (error instanceof Error && error.message === 'REQUEST_TOO_LARGE') return sendJson(response, 413, { error: '요청이 너무 큽니다.' })
      return sendJson(response, 500, { error: '회원가입을 처리하지 못했습니다.' })
    }
  }
  if (request.method === 'POST' && url.pathname === '/api/auth/login') {
    try {
      const input = await readJsonBody(request)
      const username = typeof input.username === 'string' ? input.username.trim().toLowerCase() : ''
      const password = typeof input.password === 'string' ? input.password : ''
      if (!username || !password) return sendJson(response, 400, { error: 'Username and password are required.' })
      const user = await authenticatePasswordUser({ username, password })
      return sendJson(response, 200, { user, token: createAuthToken(user.id) })
    } catch (error) {
      if (error instanceof Error && error.code === 'INVALID_CREDENTIALS') return sendJson(response, 401, { error: 'Invalid username or password.' })
      if (error instanceof Error && error.message === 'INVALID_JSON') return sendJson(response, 400, { error: 'Invalid request body.' })
      return sendJson(response, 500, { error: 'Unable to sign in.' })
    }
  }
  if (request.method === 'PUT' && url.pathname === '/api/auth/password') {
    const userId = authenticatedUserId(request)
    if (!userId) return sendJson(response, 401, { error: '로그인이 필요합니다.' })
    try {
      const input = await readJsonBody(request)
      const currentPassword = typeof input.currentPassword === 'string' ? input.currentPassword : ''
      const newPassword = typeof input.newPassword === 'string' ? input.newPassword : ''
      const passwordValidation = validatePassword(newPassword)
      if (!currentPassword || 'error' in passwordValidation) return sendJson(response, 400, { error: 'error' in passwordValidation ? passwordValidation.error : 'Current password is required.' })
      return sendJson(response, 200, { user: await changePassword({ userId, currentPassword, newPassword }) })
    } catch (error) {
      if (error instanceof Error && error.code === 'CURRENT_PASSWORD_INVALID') return sendJson(response, 401, { error: 'Current password is incorrect.' })
      if (error instanceof Error && error.code === 'PASSWORD_AUTH_UNAVAILABLE') return sendJson(response, 403, { error: 'Password changes are unavailable for social accounts.' })
      if (error instanceof Error && error.code === 'USER_NOT_FOUND') return sendJson(response, 404, { error: 'User not found.' })
      if (error instanceof Error && error.message === 'INVALID_JSON') return sendJson(response, 400, { error: 'Invalid request body.' })
      return sendJson(response, 500, { error: 'Unable to change password.' })
    }
  }
  if (request.method === 'PUT' && url.pathname === '/api/auth/me') {
    const userId = authenticatedUserId(request)
    if (!userId) return sendJson(response, 401, { error: '로그인이 필요합니다.' })
    try {
      const validation = validateProfile(await readJsonBody(request, 7_200_000))
      if ('error' in validation) return sendJson(response, 400, validation)
      return sendJson(response, 200, { user: await updateUserProfile({ userId, ...validation.value }) })
    } catch (error) {
      if (error instanceof Error && error.code === 'USER_NOT_FOUND') return sendJson(response, 404, { error: 'User not found.' })
      if (error instanceof Error && error.message === 'REQUEST_TOO_LARGE') return sendJson(response, 413, { error: 'Profile image is too large.' })
      if (error instanceof Error && error.message === 'INVALID_JSON') return sendJson(response, 400, { error: 'Invalid request body.' })
      return sendJson(response, 500, { error: 'Unable to update profile.' })
    }
  }
  if (request.method === 'DELETE' && url.pathname === '/api/auth/me') {
    const userId = authenticatedUserId(request)
    if (!userId) return sendJson(response, 401, { error: '로그인이 필요합니다.' })
    return await deleteUser(userId)
      ? sendJson(response, 200, { ok: true })
      : sendJson(response, 404, { error: 'User not found.' })
  }
  if (request.method === 'GET' && url.pathname === '/api/places') {
    const result = await findPlaces(url)
    return 'error' in result ? sendJson(response, result.status || 400, { error: result.error }) : sendJson(response, 200, result)
  }
  if (request.method === 'POST' && url.pathname === '/api/route') {
    try {
      const result = await findRoute(await readJsonBody(request))
      return 'error' in result ? sendJson(response, result.status || 400, { error: result.error }) : sendJson(response, 200, result)
    } catch (error) {
      return sendJson(response, 400, { error: error instanceof Error ? error.message : 'INVALID_ROUTE_REQUEST' })
    }
  }
  if (request.method === 'GET' && await serveStatic(url, response)) return
  return sendJson(response, 404, { error: 'Not found' })
}

server.listen(port, '0.0.0.0', () => console.log(`Where API listening on 0.0.0.0:${port}`))

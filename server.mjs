import { createServer } from 'node:http'
import { randomBytes } from 'node:crypto'
import { addFriend, authenticatePasswordUser, changePassword, createPasswordUser, createRelationshipRequest, deleteUser, initializeDatabase, listFriends, listNotifications, listOtherUsers, listUsers, respondToRelationshipRequest, siteId, updateUserProfile, upsertGoogleUser } from './database.mjs'
import { createGoogleAuthorizationUrl, fetchGoogleProfile } from './oauth.mjs'

const searchableCategories = new Set(['food', 'cafe', 'tour', 'lodging', 'activity'])
const configuredPort = Number(process.env.PORT || 3001)
const port = Number.isInteger(configuredPort) && configuredPort > 0 ? configuredPort : 3001
const frontendUrl = (process.env.FRONTEND_URL?.trim() || 'http://localhost:5173').replace(/\/$/, '')
const kakaoRestApiKey = process.env.KAKAO_REST_API_KEY?.trim() || ''
const kakaoMobilityRestApiKey = process.env.KAKAO_MOBILITY_REST_API_KEY?.trim() || ''
const cacheTtlMs = 3 * 60 * 1000
const placesCache = new Map()
const routesCache = new Map()
const kakaoCategoryCodes = { food: 'FD6', cafe: 'CE7', tour: 'AT4', photo: 'AT4', activity: 'CT1', lodging: 'AD5' }
const livePlaceMeta = {
  food: { tags: ['foodie'], groupFit: ['friends', 'couple', 'family', 'alone'] },
  cafe: { tags: ['cafe', 'rest'], groupFit: ['friends', 'couple', 'alone'] },
  tour: { tags: ['nature', 'photo', 'rest'], groupFit: ['friends', 'couple', 'family', 'alone'] },
  photo: { tags: ['photo'], groupFit: ['friends', 'couple', 'alone'] },
  activity: { tags: ['activity', 'shopping'], groupFit: ['friends', 'couple', 'family'] },
  lodging: { tags: ['rest'], groupFit: ['friends', 'couple', 'family', 'alone'] },
}
const seoulDistrictCenters = {
  강남구: [37.5172, 127.0473], 강동구: [37.5301, 127.1238], 강북구: [37.6396, 127.0257], 강서구: [37.5509, 126.8495], 관악구: [37.4784, 126.9516], 광진구: [37.5385, 127.0823], 구로구: [37.4954, 126.8874], 금천구: [37.4569, 126.8955], 노원구: [37.6542, 127.0568], 도봉구: [37.6688, 127.0471], 동대문구: [37.5744, 127.0396], 동작구: [37.5124, 126.9393], 마포구: [37.5663, 126.9019], 서대문구: [37.5791, 126.9368], 서초구: [37.4837, 127.0324], 성동구: [37.5633, 127.0371], 성북구: [37.5894, 127.0167], 송파구: [37.5145, 127.1059], 양천구: [37.5170, 126.8664], 영등포구: [37.5264, 126.8962], 용산구: [37.5326, 126.9906], 은평구: [37.6027, 126.9291], 종로구: [37.5735, 126.9788], 중구: [37.5641, 126.9979], 중랑구: [37.6063, 127.0927],
}

function sendJson(response, status, body) {
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  })
  response.end(JSON.stringify(body))
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

function frontendOAuthRedirect(response, { user, error }, cookies = []) {
  const fragment = user
    ? `oauth_user=${Buffer.from(JSON.stringify(user)).toString('base64url')}`
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
    frontendOAuthRedirect(response, { user }, [clearedCookie])
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
  return hit.value
}

function cacheValue(cache, key, value) {
  cache.set(key, { value, expiresAt: Date.now() + cacheTtlMs })
  return value
}

function haversineKm(lat1, lng1, lat2, lng2) {
  const radians = (value) => value * Math.PI / 180
  const a = Math.sin(radians(lat2 - lat1) / 2) ** 2 + Math.cos(radians(lat1)) * Math.cos(radians(lat2)) * Math.sin(radians(lng2 - lng1) / 2) ** 2
  return 6371 * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a))
}

function kakaoPlaceToPlace(item, category, origin) {
  const lat = Number(item.y); const lng = Number(item.x)
  const distanceKm = Number(haversineKm(origin.lat, origin.lng, lat, lng).toFixed(2))
  const metadata = livePlaceMeta[category] || livePlaceMeta.tour
  return { id: `kakao-${item.id}`, name: item.place_name, area: item.road_address_name || item.address_name || '서울', category: category || 'tour', lat, lng, tags: metadata.tags, groupFit: metadata.groupFit, indoor: category !== 'tour' && category !== 'photo', price: 0, durationMin: category === 'food' ? 70 : 60, rating: 0, description: item.category_name || item.place_name, image: '', accent: '#1d9b77', distanceKm, phone: item.phone || '', placeUrl: item.place_url || '' }
}

async function searchKakaoPlaces(url, category, keyword, area, companion, limit, origin) {
  if (!kakaoRestApiKey) throw new Error('KAKAO_PLACES_NOT_CONFIGURED')
  const selectedDistrict = /구$/.test(area)
  const searchKeyword = keyword
  const districtCenter = selectedDistrict ? seoulDistrictCenters[area] : null
  const searchCenter = districtCenter ? { lat: districtCenter[0], lng: districtCenter[1] } : origin
  // "전체"는 동행 유형으로 좁히지 않고, 모든 화면 카테고리를 함께 검색한다.
  // 각 카카오 응답에 카테고리를 보존해야 지도 핀도 맛집·카페·관광지·숙소·액티비티 아이콘으로 구분된다.
  const categories = category ? [category] : [...searchableCategories]
  const responses = await Promise.all(categories.map(async (placeCategory) => {
    const endpoint = searchKeyword ? 'https://dapi.kakao.com/v2/local/search/keyword.json' : 'https://dapi.kakao.com/v2/local/search/category.json'
    const params = new URLSearchParams({ size: '15', page: '1', x: String(searchCenter.lng), y: String(searchCenter.lat), radius: String(Math.min(Number(url.searchParams.get('radius') || 8000), 20000)), ...(searchKeyword ? { query: searchKeyword } : { category_group_code: kakaoCategoryCodes[placeCategory] }) })
    const response = await fetch(`${endpoint}?${params}`, { headers: { Authorization: `KakaoAK ${kakaoRestApiKey}` }, signal: AbortSignal.timeout(10_000) })
    if (!response.ok) throw new Error(`KAKAO_PLACES_${response.status}`)
    const payload = await response.json()
    const documents = selectedDistrict ? (payload.documents || []).filter((item) => `${item.address_name || ''} ${item.road_address_name || ''}`.includes(area)) : (payload.documents || [])
    return documents.map((item) => kakaoPlaceToPlace(item, placeCategory, origin))
  }))
  const data = [...new Map(responses.flat().map((place) => [place.id, place])).values()].sort((a, b) => a.distanceKm - b.distanceKm).slice(0, limit)
  return { data, meta: { total: data.length, area: area || '서울', category: category || 'all', source: 'kakao' } }
}

async function findPlaces(url) {
  const area = url.searchParams.get('area')?.trim() ?? ''
  const category = url.searchParams.get('category')?.trim() ?? ''
  const companion = url.searchParams.get('companion')?.trim() ?? ''
  const keyword = url.searchParams.get('q')?.trim().toLowerCase() ?? ''
  const requestedLimit = Number(url.searchParams.get('limit') ?? 60)
  const limit = Number.isFinite(requestedLimit) ? Math.max(1, Math.min(requestedLimit, 100)) : 60

  if (category && !searchableCategories.has(category)) {
    return { error: 'category must be food, cafe, tour, lodging, or activity' }
  }

  const origin = { lat: Number(url.searchParams.get('lat')) || 37.5668, lng: Number(url.searchParams.get('lng')) || 126.978 }
  const cacheKey = JSON.stringify({ area, category, companion, keyword, limit, lat: origin.lat.toFixed(4), lng: origin.lng.toFixed(4), radius: url.searchParams.get('radius') || '' })
  const cached = fromCache(placesCache, cacheKey)
  if (cached) return cached
  try {
    return cacheValue(placesCache, cacheKey, await searchKakaoPlaces(url, category, keyword, area, companion, limit, origin))
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
    const response = await fetch(`https://apis-navi.kakaomobility.com/v1/directions?${params}`, {
      headers: { Authorization: `KakaoAK ${kakaoMobilityRestApiKey}` },
      signal: AbortSignal.timeout(10_000),
    })
    if (!response.ok) throw new Error(`KAKAO_ROUTE_${response.status}`)
    const payload = await response.json()
    const summary = payload.routes?.[0]?.summary
    const coordinates = routeCoordinates(payload)
    if (!summary || coordinates.length < 2) throw new Error('KAKAO_ROUTE_EMPTY')
    return cacheValue(routesCache, cacheKey, { data: { coordinates, distanceMeters: summary.distance, durationSeconds: summary.duration } })
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

await initializeDatabase()

createServer(async (request, response) => {
  const url = new URL(request.url ?? '/', 'http://localhost:3001')
  if (request.method === 'OPTIONS') return sendJson(response, 204, {})
  if (request.method === 'GET' && url.pathname === '/') return sendJson(response, 200, {
    name: 'Where Backend API',
    health: '/api/health',
  })
  if (request.method === 'GET' && url.pathname === '/api/health') return sendJson(response, 200, { ok: true, database: 'postgresql', siteId })
  if (request.method === 'GET' && url.pathname === '/api/auth/oauth/google') return startGoogleOAuth(request, response)
  if (request.method === 'GET' && url.pathname === '/api/auth/oauth/google/callback') return completeGoogleOAuth(request, response, url)
  if (request.method === 'GET' && url.pathname === '/api/auth/users') return sendJson(response, 200, { data: await listUsers() })
  if (request.method === 'GET' && url.pathname === '/api/social/users') {
    const userId = url.searchParams.get('userId')
    if (!userId) return sendJson(response, 400, { error: 'userId is required' })
    return sendJson(response, 200, { data: await listOtherUsers(userId) })
  }
  if (request.method === 'GET' && url.pathname === '/api/social/friends') {
    const userId = url.searchParams.get('userId')
    if (!userId) return sendJson(response, 400, { error: 'userId is required' })
    return sendJson(response, 200, { data: await listFriends(userId) })
  }
  if (request.method === 'GET' && url.pathname === '/api/social/notifications') {
    const userId = url.searchParams.get('userId')
    if (!userId) return sendJson(response, 400, { error: 'userId is required' })
    return sendJson(response, 200, { data: await listNotifications(userId) })
  }
  if (request.method === 'POST' && url.pathname === '/api/social/friends') {
    try {
      const { userId, friendId } = await readJsonBody(request)
      if (typeof userId !== 'string' || typeof friendId !== 'string') return sendJson(response, 400, { error: 'userId and friendId are required' })
      await addFriend(userId, friendId)
      return sendJson(response, 201, { ok: true })
    } catch (error) { return sendJson(response, 400, { error: error instanceof Error ? error.message : 'FRIEND_ADD_FAILED' }) }
  }
  if (request.method === 'POST' && url.pathname === '/api/social/relationship-requests') {
    try {
      const { userId, recipientId, relationshipType } = await readJsonBody(request)
      if (typeof userId !== 'string' || typeof recipientId !== 'string' || !['friend', 'couple', 'family'].includes(relationshipType)) return sendJson(response, 400, { error: 'invalid relationship request' })
      return sendJson(response, 201, { data: await createRelationshipRequest(userId, recipientId, relationshipType) })
    } catch (error) { return sendJson(response, 400, { error: error instanceof Error ? error.message : 'RELATIONSHIP_REQUEST_FAILED' }) }
  }
  if (request.method === 'POST' && /^\/api\/social\/notifications\/[^/]+\/respond$/.test(url.pathname)) {
    try {
      const requestId = url.pathname.split('/')[4]
      const { userId, accepted } = await readJsonBody(request)
      if (typeof userId !== 'string' || typeof accepted !== 'boolean') return sendJson(response, 400, { error: 'invalid notification response' })
      return sendJson(response, 200, { data: await respondToRelationshipRequest(userId, requestId, accepted) })
    } catch (error) { return sendJson(response, 400, { error: error instanceof Error ? error.message : 'NOTIFICATION_RESPONSE_FAILED' }) }
  }
  if (request.method === 'POST' && url.pathname === '/api/auth/signup') {
    try {
      const validation = validateSignup(await readJsonBody(request))
      if ('error' in validation) return sendJson(response, 400, validation)
      return sendJson(response, 201, { user: await createPasswordUser(validation.value) })
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
      return sendJson(response, 200, { user: await authenticatePasswordUser({ username, password }) })
    } catch (error) {
      if (error instanceof Error && error.code === 'INVALID_CREDENTIALS') return sendJson(response, 401, { error: 'Invalid username or password.' })
      if (error instanceof Error && error.message === 'INVALID_JSON') return sendJson(response, 400, { error: 'Invalid request body.' })
      return sendJson(response, 500, { error: 'Unable to sign in.' })
    }
  }
  if (request.method === 'PUT' && url.pathname === '/api/auth/password') {
    try {
      const input = await readJsonBody(request)
      const userId = typeof input.userId === 'string' ? input.userId : ''
      const currentPassword = typeof input.currentPassword === 'string' ? input.currentPassword : ''
      const newPassword = typeof input.newPassword === 'string' ? input.newPassword : ''
      const passwordValidation = validatePassword(newPassword)
      if (!userId || !currentPassword || 'error' in passwordValidation) return sendJson(response, 400, { error: 'error' in passwordValidation ? passwordValidation.error : 'Current password is required.' })
      return sendJson(response, 200, { user: await changePassword({ userId, currentPassword, newPassword }) })
    } catch (error) {
      if (error instanceof Error && error.code === 'CURRENT_PASSWORD_INVALID') return sendJson(response, 401, { error: 'Current password is incorrect.' })
      if (error instanceof Error && error.code === 'PASSWORD_AUTH_UNAVAILABLE') return sendJson(response, 403, { error: 'Password changes are unavailable for social accounts.' })
      if (error instanceof Error && error.code === 'USER_NOT_FOUND') return sendJson(response, 404, { error: 'User not found.' })
      if (error instanceof Error && error.message === 'INVALID_JSON') return sendJson(response, 400, { error: 'Invalid request body.' })
      return sendJson(response, 500, { error: 'Unable to change password.' })
    }
  }
  if (request.method === 'PUT' && /^\/api\/auth\/users\/[^/]+$/.test(url.pathname)) {
    try {
      const validation = validateProfile(await readJsonBody(request, 7_200_000))
      if ('error' in validation) return sendJson(response, 400, validation)
      const userId = url.pathname.split('/').at(-1)
      return sendJson(response, 200, { user: await updateUserProfile({ userId, ...validation.value }) })
    } catch (error) {
      if (error instanceof Error && error.code === 'USER_NOT_FOUND') return sendJson(response, 404, { error: 'User not found.' })
      if (error instanceof Error && error.message === 'REQUEST_TOO_LARGE') return sendJson(response, 413, { error: 'Profile image is too large.' })
      if (error instanceof Error && error.message === 'INVALID_JSON') return sendJson(response, 400, { error: 'Invalid request body.' })
      return sendJson(response, 500, { error: 'Unable to update profile.' })
    }
  }
  if (request.method === 'DELETE' && /^\/api\/auth\/users\/[^/]+$/.test(url.pathname)) {
    const userId = url.pathname.split('/').at(-1)
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
  return sendJson(response, 404, { error: 'Not found' })
}).listen(port, () => console.log(`Where API: http://localhost:${port}`))

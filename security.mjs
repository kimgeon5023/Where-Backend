export function allowedOrigins({ frontendUrl = '', nodeEnv = process.env.NODE_ENV || 'production' } = {}) {
  const values = frontendUrl.split(',').map((value) => value.trim().replace(/\/$/, '')).filter(Boolean)
  if (nodeEnv !== 'production') values.push('http://localhost:5173', 'http://127.0.0.1:5173')
  return new Set(values)
}

export function allowedOrigin(origin, origins) {
  if (!origin) return null
  return origins.has(origin.replace(/\/$/, '')) ? origin : null
}

export function requestIp(request) {
  const forwarded = request.headers['x-forwarded-for']
  return typeof forwarded === 'string' ? forwarded.split(',')[0].trim() : request.socket?.remoteAddress || 'unknown'
}

export function createRateLimiter({ now = () => Date.now() } = {}) {
  const buckets = new Map()
  return ({ key, limit, windowMs }) => {
    const time = now(); const current = buckets.get(key)
    const active = current && current.resetAt > time ? current : { count: 0, resetAt: time + windowMs }
    active.count += 1; buckets.set(key, active)
    return { allowed: active.count <= limit, retryAfterSeconds: Math.max(1, Math.ceil((active.resetAt - time) / 1000)) }
  }
}


import { OAuth2Client } from 'google-auth-library'

const google = {
  authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
  tokenUrl: 'https://oauth2.googleapis.com/token',
  clientId: () => process.env.GOOGLE_CLIENT_ID?.trim(),
  clientSecret: () => process.env.GOOGLE_CLIENT_SECRET?.trim(),
}

const googleTokenVerifier = new OAuth2Client()

function googleConfig() {
  if (!google.clientId() || !google.clientSecret()) throw new Error('OAUTH_PROVIDER_NOT_CONFIGURED')
  return google
}

export function createGoogleAuthorizationUrl({ redirectUri, state }) {
  const config = googleConfig()
  const parameters = new URLSearchParams({
    client_id: config.clientId(),
    redirect_uri: redirectUri,
    response_type: 'code',
    state,
  })

  parameters.set('scope', 'openid email profile')
  parameters.set('prompt', 'select_account')

  return `${config.authorizationUrl}?${parameters}`
}

async function tokenRequest(code, redirectUri) {
  const config = googleConfig()
  const parameters = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: config.clientId(),
    client_secret: config.clientSecret(),
    redirect_uri: redirectUri,
    code,
  })
  const response = await fetch(config.tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8' },
    body: parameters,
    signal: AbortSignal.timeout(15_000),
  })
  const body = await response.json().catch(() => ({}))
  if (!response.ok || !body.access_token) throw new Error('OAUTH_TOKEN_EXCHANGE_FAILED')
  return body.access_token
}

async function fetchGoogleUserInfo(accessToken) {
  const response = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
    headers: { Authorization: `Bearer ${accessToken}` },
    signal: AbortSignal.timeout(15_000),
  })
  const profile = await response.json().catch(() => ({}))
  if (!response.ok || !profile.sub) throw new Error('OAUTH_PROFILE_FAILED')
  return {
    providerUserId: profile.sub,
    name: profile.name,
    email: profile.email,
    profileImage: profile.picture,
  }
}

export async function fetchGoogleProfile(code, redirectUri) {
  const accessToken = await tokenRequest(code, redirectUri)
  return fetchGoogleUserInfo(accessToken)
}

export async function verifyGoogleIdToken(idToken) {
  const clientId = google.clientId()
  if (!clientId) throw new Error('OAUTH_PROVIDER_NOT_CONFIGURED')
  if (typeof idToken !== 'string' || !idToken.trim()) throw new Error('GOOGLE_ID_TOKEN_REQUIRED')

  const ticket = await googleTokenVerifier.verifyIdToken({ idToken, audience: clientId })
  const profile = ticket.getPayload()
  if (!profile?.sub || !profile.email || profile.email_verified !== true) throw new Error('GOOGLE_ID_TOKEN_INVALID')

  return {
    providerUserId: profile.sub,
    name: profile.name || profile.email.split('@')[0],
    email: profile.email,
    profileImage: profile.picture || '',
  }
}

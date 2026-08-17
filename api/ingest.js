import { neon } from '@neondatabase/serverless'
import crypto from 'node:crypto'

const sql = neon(process.env.DATABASE_URL)

function hash(value) {
  return crypto.createHash('sha256').update(value).digest('hex')
}

function sameSecret(a, b) {
  const aa = Buffer.from(a)
  const bb = Buffer.from(b)
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb)
}

function isValidIp(value) {
  if (!value || typeof value !== 'string') return false

  // IPv4
  const ipv4 =
    /^(?:\d{1,3}\.){3}\d{1,3}$/

  // IPv6 - basic validation; PostgreSQL does the final validation
  const ipv6 = value.includes(':')

  return ipv4.test(value) || ipv6
}

export default async function handler(req, res) {
  // CORS / preflight must be handled before the method check.
  const origin = req.headers.origin

  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin)
    res.setHeader('Vary', 'Origin')
  }

  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS')
  res.setHeader(
    'Access-Control-Allow-Headers',
    'Authorization, Content-Type, X-Original-Client-IP, X-Original-User-Agent'
  )

  if (req.method === 'OPTIONS') {
    return res.status(204).end()
  }

  if (req.method !== 'POST') {
    return res.status(405).json({
      error: 'Method not allowed',
    })
  }

  try {
    // --------------------------------------------------
    // 1. Authenticate the project
    // --------------------------------------------------

    const auth = req.headers.authorization || ''
    const suppliedKey = auth.startsWith('Bearer ')
      ? auth.slice(7)
      : ''

    if (!suppliedKey) {
      return res.status(401).json({
        error: 'Missing API key',
      })
    }

    const result = await sql`
      SELECT id, name, api_key_hash, enabled
      FROM logger_projects
      WHERE enabled = true
    `

    const suppliedHash = hash(suppliedKey)

    const project = result.find((row) =>
      sameSecret(suppliedHash, row.api_key_hash)
    )

    if (!project) {
      return res.status(401).json({
        error: 'Invalid API key',
      })
    }

    // --------------------------------------------------
    // 2. Validate event
    // --------------------------------------------------

    const body =
      typeof req.body === 'object' && req.body
        ? req.body
        : {}

    const event =
      typeof body.event === 'string'
        ? body.event.slice(0, 100)
        : null

    if (!event) {
      return res.status(400).json({
        error: 'event is required',
      })
    }

    const success =
      typeof body.success === 'boolean'
        ? body.success
        : null

    const metadata =
      body.metadata &&
      typeof body.metadata === 'object'
        ? body.metadata
        : {}

    // --------------------------------------------------
    // 3. Get ORIGINAL client information
    //
    // These headers are supplied by the authenticated
    // TKA server, not by the browser directly.
    // --------------------------------------------------

    const originalIp =
      typeof req.headers['x-original-client-ip'] === 'string'
        ? req.headers['x-original-client-ip'].trim()
        : ''

    const originalUserAgent =
      typeof req.headers['x-original-user-agent'] === 'string'
        ? req.headers['x-original-user-agent']
        : ''

    const ip = isValidIp(originalIp)
      ? originalIp
      : null

    const userAgent = (
      originalUserAgent ||
      'unknown'
    ).slice(0, 1000)

    // --------------------------------------------------
    // 4. Store event
    // --------------------------------------------------

    await sql`
      INSERT INTO logger_events
        (
          project_id,
          event,
          success,
          ip,
          user_agent,
          metadata
        )
      VALUES
        (
          ${project.id},
          ${event},
          ${success},
          ${ip},
          ${userAgent},
          ${JSON.stringify(metadata)}
        )
    `
    return res.status(204).end()

  } catch (error) {
    console.error('ingest error', error)

    return res.status(500).json({
      error: 'Internal server error',
    })
  }
}
import { neon } from '@neondatabase/serverless'
import crypto from 'node:crypto'

const sql = neon(process.env.DATABASE_URL)

function getIp(req) {
  const forwarded = req.headers['x-forwarded-for']
  if (forwarded) return forwarded.split(',')[0].trim()
  return req.headers['x-real-ip'] || 'unknown'
}

function hash(value) {
  return crypto.createHash('sha256').update(value).digest('hex')
}

function sameSecret(a, b) {
  const aa = Buffer.from(a)
  const bb = Buffer.from(b)
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb)
}

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' })

  const origin = req.headers.origin
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin)
    res.setHeader('Vary', 'Origin')
  }
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type')
  if (req.method === 'OPTIONS') return res.status(204).end()

  try {
    const auth = req.headers.authorization || ''
    const suppliedKey = auth.startsWith('Bearer ') ? auth.slice(7) : ''
    if (!suppliedKey) return res.status(401).json({ error: 'Missing API key' })

    const result = await sql`
      SELECT id, name, api_key_hash, enabled
      FROM logger_projects
      WHERE enabled = true
    `
    const project = result.find(row => sameSecret(hash(suppliedKey), row.api_key_hash))
    if (!project) return res.status(401).json({ error: 'Invalid API key' })

    const body = typeof req.body === 'object' && req.body ? req.body : {}
    const event = typeof body.event === 'string' ? body.event.slice(0, 100) : null
    if (!event) return res.status(400).json({ error: 'event is required' })

    const success = typeof body.success === 'boolean' ? body.success : null
    const metadata = body.metadata && typeof body.metadata === 'object' ? body.metadata : {}
    const ip = getIp(req)
    const userAgent = String(req.headers['user-agent'] || '').slice(0, 1000)

    await sql`
      INSERT INTO logger_events
        (project_id, event, success, ip, user_agent, metadata)
      VALUES
        (${project.id}, ${event}, ${success}, ${ip}, ${userAgent}, ${JSON.stringify(metadata)})
    `

    return res.status(204).end()
  } catch (error) {
    console.error('ingest error', error)
    return res.status(500).json({ error: 'Internal server error' })
  }
}

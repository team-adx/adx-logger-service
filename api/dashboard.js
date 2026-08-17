import { neon } from '@neondatabase/serverless'
import bcrypt from 'bcryptjs'
import crypto from 'node:crypto'

const sql = neon(process.env.DATABASE_URL)
const COOKIE = 'logger_session'

function getIp(req) {
  const forwarded = req.headers['x-forwarded-for']
  if (forwarded) return forwarded.split(',')[0].trim()
  return req.headers['x-real-ip'] || 'unknown'
}

function parseCookies(req) {
  const raw = req.headers.cookie || ''
  return Object.fromEntries(raw.split(';').map(x => {
    const i = x.indexOf('=')
    return i === -1 ? [x.trim(), ''] : [x.slice(0, i).trim(), decodeURIComponent(x.slice(i + 1))]
  }).filter(([k]) => k))
}

function newToken() {
  return crypto.randomBytes(32).toString('base64url')
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex')
}

async function authorize(req) {
  const cookies = parseCookies(req)
  const token = cookies[COOKIE]
  if (!token) return null

  const rows = await sql`
    SELECT u.id, u.username
    FROM logger_sessions s
    JOIN logger_users u ON u.id = s.user_id
    WHERE s.token_hash = ${sha256(token)}
      AND s.expires_at > NOW()
      AND u.enabled = true
    LIMIT 1
  `
  if (!rows.length) return null

  const allowed = await sql`SELECT cidr FROM logger_allowed_ips`
  if (allowed.length) {
    const ip = getIp(req)
    const ipRows = await sql`
      SELECT 1
      FROM logger_allowed_ips
      WHERE cidr >>= ${ip}::inet
      LIMIT 1
    `
    if (!ipRows.length) return null
  }

  return rows[0]
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store')

  try {
    if (req.method === 'POST') {
      const body = typeof req.body === 'object' && req.body ? req.body : {}

      if (body.action === 'logout') {
        const cookies = parseCookies(req)
        if (cookies[COOKIE]) {
          await sql`DELETE FROM logger_sessions WHERE token_hash = ${sha256(cookies[COOKIE])}`
        }
        res.setHeader('Set-Cookie', `${COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`)
        return res.status(204).end()
      }

      if (body.action === 'login') {
        const username = typeof body.username === 'string' ? body.username.slice(0, 100) : ''
        const password = typeof body.password === 'string' ? body.password : ''
        if (!username || !password) return res.status(400).json({ error: 'Username and password required' })

        const users = await sql`
          SELECT id, password_hash
          FROM logger_users
          WHERE username = ${username} AND enabled = true
          LIMIT 1
        `
        if (!users.length || !(await bcrypt.compare(password, users[0].password_hash))) {
          return res.status(401).json({ error: 'Invalid credentials' })
        }

        const token = newToken()
        await sql`
          INSERT INTO logger_sessions (user_id, token_hash, expires_at)
          VALUES (${users[0].id}, ${sha256(token)}, NOW() + INTERVAL '24 hours')
        `
        res.setHeader('Set-Cookie', `${COOKIE}=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=86400`)
        return res.status(204).end()
      }

      return res.status(400).json({ error: 'Unknown action' })
    }

    if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' })

    const user = await authorize(req)
    if (!user) return res.status(401).json({ error: 'Unauthorized' })

    const limitRaw = Number(req.query.limit || 500)
    const limit = Math.min(Math.max(Number.isFinite(limitRaw) ? limitRaw : 500, 1), 1000)

    const logs = await sql`
      SELECT
        e.id,
        p.name AS project,
        e.event,
        e.success,
        e.ip,
        e.user_agent,
        e.metadata,
        e.created_at
      FROM logger_events e
      JOIN logger_projects p ON p.id = e.project_id
      WHERE e.created_at >= NOW() - INTERVAL '30 days'
      ORDER BY e.created_at DESC
      LIMIT ${limit}
    `
    const projectRows = await sql`SELECT name FROM logger_projects WHERE enabled = true ORDER BY name`

    return res.status(200).json({
      logs,
      projects: projectRows.map(x => x.name),
    })
  } catch (error) {
    console.error('dashboard error', error)
    return res.status(500).json({ error: 'Internal server error' })
  }
}

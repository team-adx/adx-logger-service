import { neon } from '@neondatabase/serverless'

const sql = neon(process.env.DATABASE_URL)

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' })
  }

  const auth = req.headers.authorization
  const expected = `Bearer ${process.env.CRON_SECRET}`

  if (!process.env.CRON_SECRET || auth !== expected) {
    return res.status(401).json({ error: 'Unauthorized' })
  }

  try {
    const deletedEvents = await sql`
      DELETE FROM logger_events
      WHERE created_at < NOW() - INTERVAL '7 days'
    `

    const deletedSessions = await sql`
      DELETE FROM logger_sessions
      WHERE expires_at < NOW()
    `

    return res.status(200).json({
      ok: true,
      deletedEvents: deletedEvents.count ?? 0,
      deletedSessions: deletedSessions.count ?? 0,
    })
  } catch (error) {
    console.error('Cleanup failed:', error)

    return res.status(500).json({
      error: 'Cleanup failed',
    })
  }
}
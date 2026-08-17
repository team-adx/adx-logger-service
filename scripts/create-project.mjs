import crypto from 'node:crypto'
import { neon } from '@neondatabase/serverless'

const [, , name] = process.argv
if (!name) {
  console.error('Usage: node scripts/create-project.mjs <project-name>')
  process.exit(1)
}

const sql = neon(process.env.DATABASE_URL)
const key = crypto.randomBytes(32).toString('base64url')
const hash = crypto.createHash('sha256').update(key).digest('hex')

await sql`
  INSERT INTO logger_projects (name, api_key_hash)
  VALUES (${name}, ${hash})
`

console.log(`Project: ${name}`)
console.log(`API key: ${key}`)
console.log('SAVE THIS KEY NOW. It cannot be recovered from the database.')

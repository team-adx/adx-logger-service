# Logger

A private, multi-project request/event logger designed for Vercel + Neon.

## Architecture

Only two Vercel serverless functions are used:

- `POST /api/ingest` — project API-key authenticated event ingestion.
- `/api/dashboard` — dashboard login, session management, and log querying.

The dashboard itself is static Vue/Vite.

## Security model

### Project ingestion

Each project gets its own random API key. The plaintext key is only given once; only its SHA-256 hash is stored.

Send:

```http
Authorization: Bearer YOUR_PROJECT_API_KEY
Content-Type: application/json
```

Example:

```js
await fetch('https://logger.example.com/api/ingest', {
  method: 'POST',
  headers: {
    Authorization: `Bearer ${process.env.LOGGER_API_KEY}`,
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    event: 'admin_login',
    success: false,
    metadata: {
      username: 'admin'
    }
  })
})
```

The logger determines the source IP server-side and does not trust an `ip` field supplied by the caller.

### Dashboard

Dashboard users are stored in Neon with bcrypt password hashes. Sessions are random opaque tokens stored only as SHA-256 hashes and sent as `HttpOnly`, `Secure`, `SameSite=Strict` cookies.

An optional IP allowlist is supported. If `logger_allowed_ips` is empty, user/password authentication is sufficient. If it contains entries, the request IP must also fall inside one of the allowed CIDRs.

## Setup

1. Create a Neon database.
2. Run `sql/schema.sql` in the Neon SQL Editor.
3. Set Vercel environment variables:
   - `DATABASE_URL`
   - `SESSION_SECRET` (reserved for future token/signing features; use a long random value)
4. Create the first dashboard user manually:

```sql
INSERT INTO logger_users (username, password_hash)
VALUES ('admin', 'PASTE_BCRYPT_HASH_HERE');
```

Generate the hash locally:

```bash
npm install
npm run hash-password
```

5. Create a project API key locally:

```bash
DATABASE_URL="your-neon-url" node scripts/create-project.mjs tka
```

6. Deploy to Vercel.

## Optional IP allowlist

For a fixed home/office IP:

```sql
INSERT INTO logger_allowed_ips (cidr)
VALUES ('203.0.113.42/32');
```

For a subnet:

```sql
INSERT INTO logger_allowed_ips (cidr)
VALUES ('203.0.113.0/24');
```

To disable IP restriction, remove all rows from `logger_allowed_ips`.

## Retention

Neon `pg_cron` runs the cleanup daily. Events older than 30 days are deleted.

The dashboard also only queries the last 30 days.

## Notes

Do not send passwords, cookies, JWTs, authorization headers, or other secrets as event metadata. Log only what you actually need for security/auditing.

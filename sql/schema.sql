CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_cron;

CREATE TABLE IF NOT EXISTS logger_projects (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL UNIQUE,
  api_key_hash CHAR(64) NOT NULL UNIQUE,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS logger_users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS logger_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES logger_users(id) ON DELETE CASCADE,
  token_hash CHAR(64) NOT NULL UNIQUE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS logger_allowed_ips (
  id BIGSERIAL PRIMARY KEY,
  cidr CIDR NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS logger_events (
  id BIGSERIAL PRIMARY KEY,
  project_id UUID NOT NULL REFERENCES logger_projects(id) ON DELETE CASCADE,
  event TEXT NOT NULL,
  success BOOLEAN,
  ip INET,
  user_agent TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS logger_events_created_at_idx ON logger_events (created_at DESC);
CREATE INDEX IF NOT EXISTS logger_events_project_created_idx ON logger_events (project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS logger_events_ip_idx ON logger_events (ip);
CREATE INDEX IF NOT EXISTS logger_sessions_expires_idx ON logger_sessions (expires_at);

-- Delete anything older than 30 days every day at 03:15 UTC.
SELECT cron.schedule(
  'logger-30-day-retention',
  '15 3 * * *',
  $$DELETE FROM logger_events WHERE created_at < NOW() - INTERVAL '30 days'$$
);

-- Expired login sessions are cleaned at the same time.
SELECT cron.schedule(
  'logger-expired-sessions',
  '20 3 * * *',
  $$DELETE FROM logger_sessions WHERE expires_at < NOW()$$
);

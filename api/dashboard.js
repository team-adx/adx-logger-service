import bcrypt from "bcrypt";
import { neon } from "@neondatabase/serverless";
import crypto from "crypto";

const sql = neon(process.env.DATABASE_URL);
const SESSION_COOKIE = "logger_session";
const SESSION_DAYS = 7;

function setCookie(res, name, value, maxAge) {
  const parts = [
    `${name}=${value}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Strict",
  ];

  if (maxAge !== undefined) {
    parts.push(`Max-Age=${maxAge}`);
  }

  res.setHeader("Set-Cookie", parts.join("; "));
}

function getCookie(req, name) {
  const cookies = req.headers.cookie || "";

  const match = cookies
    .split(";")
    .map((c) => c.trim())
    .find((c) => c.startsWith(`${name}=`));

  return match ? decodeURIComponent(match.substring(name.length + 1)) : null;
}

async function getSession(req) {
  const token = getCookie(req, SESSION_COOKIE);

  if (!token) {
    return null;
  }

  const rows = await sql`
    SELECT
      s.id,
      u.id AS user_id,
      u.username,
      u.role,
      u.enabled
    FROM logger_sessions s
    JOIN logger_users u
      ON u.id = s.user_id
    WHERE s.token_hash = ${crypto
      .createHash("sha256")
      .update(token)
      .digest("hex")}
      AND s.expires_at > NOW()
    LIMIT 1
  `;

  if (!rows.length) {
    return null;
  }

  if (!rows[0].enabled) {
    return null;
  }

  return rows[0];
}

async function login(req, res) {
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({
      error: "Username and password are required",
    });
  }

  const users = await sql`
    SELECT id, username, password_hash, role, enabled
    FROM logger_users
    WHERE username = ${username}
    LIMIT 1
  `;

  if (!users.length || !users[0].enabled) {
    return res.status(401).json({
      error: "Invalid username or password",
    });
  }

  const user = users[0];

  const valid = await bcrypt.compare(
    password,
    user.password_hash
  );

  if (!valid) {
    return res.status(401).json({
      error: "Invalid username or password",
    });
  }

  const rawToken = crypto.randomBytes(32).toString("hex");

  const tokenHash = crypto
    .createHash("sha256")
    .update(rawToken)
    .digest("hex");

  const expiresAt = new Date(
    Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000
  );

  await sql`
    INSERT INTO logger_sessions (
      user_id,
      token_hash,
      expires_at
    )
    VALUES (
      ${user.id},
      ${tokenHash},
      ${expiresAt}
    )
  `;

  setCookie(
    res,
    SESSION_COOKIE,
    rawToken,
    SESSION_DAYS * 24 * 60 * 60
  );

  return res.status(200).json({
    success: true,
    user: {
      id: user.id,
      username: user.username,
      role: user.role,
    },
  });
}

async function logout(req, res) {
  const token = getCookie(req, SESSION_COOKIE);

  if (token) {
    const tokenHash = crypto
      .createHash("sha256")
      .update(token)
      .digest("hex");

    await sql`
      DELETE FROM logger_sessions
      WHERE token_hash = ${tokenHash}
    `;
  }

  setCookie(res, SESSION_COOKIE, "", 0);

  return res.status(200).json({
    success: true,
  });
}

async function getProjects(session) {
  if (session.role === "MASTER") {
    return sql`
      SELECT
        id,
        name,
        enabled,
        created_at
      FROM logger_projects
      WHERE enabled = TRUE
      ORDER BY name ASC
    `;
  }

  return sql`
    SELECT
      p.id,
      p.name,
      p.enabled,
      p.created_at
    FROM logger_projects p
    JOIN logger_project_members pm
      ON pm.project_id = p.id
    WHERE pm.user_id = ${session.user_id}
      AND p.enabled = TRUE
    ORDER BY p.name ASC
  `;
}

async function getLogs(req, res, session) {
  const limitRaw = Number(req.query?.limit || 100);
  const limit = Math.min(
    Math.max(limitRaw, 1),
    500
  );

  const projectId = req.query?.project_id || null;
  const event = req.query?.event || null;
  const ip = req.query?.ip || null;

  let rows;

  if (session.role === "MASTER") {
    rows = await sql`
      SELECT
        e.id,
        e.project_id,
        p.name AS project,
        e.event,
        e.success,
        e.ip,
        e.user_agent,
        e.metadata,
        e.created_at
      FROM logger_events e
      JOIN logger_projects p
        ON p.id = e.project_id
      WHERE
        (${projectId}::uuid IS NULL OR e.project_id = ${projectId}::uuid)
        AND (${event}::text IS NULL OR e.event = ${event})
        AND (${ip}::text IS NULL OR e.ip = ${ip})
      ORDER BY e.created_at DESC
      LIMIT ${limit}
    `;
  } else {
    rows = await sql`
      SELECT
        e.id,
        e.project_id,
        p.name AS project,
        e.event,
        e.success,
        e.ip,
        e.user_agent,
        e.metadata,
        e.created_at
      FROM logger_events e
      JOIN logger_projects p
        ON p.id = e.project_id
      JOIN logger_project_members pm
        ON pm.project_id = e.project_id
      WHERE
        pm.user_id = ${session.user_id}
        AND (${projectId}::uuid IS NULL OR e.project_id = ${projectId}::uuid)
        AND (${event}::text IS NULL OR e.event = ${event})
        AND (${ip}::text IS NULL OR e.ip = ${ip})
      ORDER BY e.created_at DESC
      LIMIT ${limit}
    `;
  }

  return res.status(200).json({
    success: true,
    logs: rows,
  });
}

export default async function handler(req, res) {
  try {
    /*
     * LOGIN
     */
    if (
      req.method === "POST" &&
      req.body?.action === "login"
    ) {
      return await login(req, res);
    }

    /*
     * LOGOUT
     */
    if (
      req.method === "POST" &&
      req.body?.action === "logout"
    ) {
      return await logout(req, res);
    }

    /*
     * Everything below requires authentication.
     */
    const session = await getSession(req);

    if (!session) {
      return res.status(401).json({
        error: "Unauthorized",
      });
    }

    /*
     * CURRENT USER
     */
    if (
      req.method === "GET" &&
      req.query?.action === "me"
    ) {
      return res.status(200).json({
        success: true,
        user: {
          id: session.user_id,
          username: session.username,
          role: session.role,
        },
      });
    }

    /*
     * PROJECTS AVAILABLE TO THIS USER
     */
    if (
      req.method === "GET" &&
      req.query?.action === "projects"
    ) {
      const projects = await getProjects(session);

      return res.status(200).json({
        success: true,
        projects,
      });
    }

    /*
     * LOGS
     */
    if (
      req.method === "GET" &&
      (!req.query?.action || req.query?.action === "logs")
    ) {
      return await getLogs(req, res, session);
    }

    return res.status(400).json({
      error: "Invalid action",
    });

  } catch (err) {
    console.error("Dashboard API error:", err);

    return res.status(500).json({
      error: "Internal server error",
    });
  }
}
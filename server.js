#!/usr/bin/env node
import express from "express";
import cors from "cors";
import multer from "multer";
import { v4 as uuid } from "uuid";
import fs from "fs";
import path from "path";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import { initDb, run, all, get, transaction, getDbInfo } from "./dbClient.js";

const app = express();
app.use(cors());
app.use(express.json({ limit: "10mb" }));

const DB_PATH = process.env.NEXUS_DB || path.join(process.cwd(), "data", "nexus.db");
initDb(DB_PATH);

const uploadDir = (() => {
  const target = process.env.UPLOAD_DIR || path.join(process.cwd(), "uploads");
  if (target.startsWith("s3://")) {
    // Placeholder: S3 not yet implemented, store local for now
    const local = path.join(process.cwd(), "uploads");
    fs.mkdirSync(local, { recursive: true });
    return local;
  }
  fs.mkdirSync(target, { recursive: true });
  return target;
})();
const upload = multer({ dest: uploadDir });
app.use("/uploads", express.static(uploadDir));

async function ensureAuthColumns() {
  // For SQLite only; PG schema uses CREATE TABLE IF NOT EXISTS
  try {
    await run("ALTER TABLE users ADD COLUMN password_hash TEXT");
  } catch (_) {}
  try {
    await run("ALTER TABLE users ADD COLUMN password_salt TEXT");
  } catch (_) {}
}

async function migrate() {
  const statements = [
    "CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, display_name TEXT NOT NULL, email TEXT, password_hash TEXT, password_salt TEXT, created_at TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS projects (id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS project_members (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, user_id TEXT NOT NULL, capabilities_json TEXT NOT NULL, created_at TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS work_items (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, type TEXT NOT NULL, title TEXT NOT NULL, description TEXT, current_step TEXT NOT NULL, status TEXT NOT NULL, external_link TEXT, created_by_user_id TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS task_instances (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, work_item_id TEXT NOT NULL, owner_user_id TEXT NOT NULL, date TEXT NOT NULL, title TEXT NOT NULL, step_key TEXT NOT NULL, estimate_min INTEGER, state TEXT NOT NULL, start_at TEXT, end_at TEXT, time_spent_sec INTEGER DEFAULT 0, done_summary TEXT, blockers TEXT, visibility TEXT NOT NULL DEFAULT 'PRIVATE', submitted_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS evidence (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, task_instance_id TEXT NOT NULL, type TEXT NOT NULL, uri TEXT NOT NULL, meta_json TEXT NOT NULL, is_keyframe INTEGER NOT NULL DEFAULT 0, visibility TEXT NOT NULL DEFAULT 'PRIVATE', created_at TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS artifacts (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, work_item_id TEXT NOT NULL, step_key TEXT NOT NULL, type TEXT NOT NULL, value_type TEXT NOT NULL, value TEXT NOT NULL, visibility TEXT NOT NULL DEFAULT 'PUBLIC', created_by_user_id TEXT NOT NULL, created_at TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS compliance_records (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, work_item_id TEXT NOT NULL, step_key TEXT NOT NULL, status TEXT NOT NULL, missing_artifacts_json TEXT NOT NULL, notes TEXT, updated_at TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS task_reviews (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, task_instance_id TEXT NOT NULL, reviewer_user_id TEXT NOT NULL, action TEXT NOT NULL, note TEXT, from_visibility TEXT, to_visibility TEXT, created_at TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS refresh_tokens (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, token_hash TEXT NOT NULL, expires_at TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL)",
  ];
  for (const stmt of statements) {
    await run(stmt);
  }
  await ensureAuthColumns();
}
migrate();

const JWT_SECRET = process.env.NEXUS_JWT_SECRET || "dev-secret";
const ACCESS_TTL = "30m";
const REFRESH_DAYS = 30;

function now() {
  return new Date().toISOString();
}

function signAccess(userId) {
  return jwt.sign({ sub: userId }, JWT_SECRET, { expiresIn: ACCESS_TTL });
}

async function issueRefresh(userId) {
  const token = uuid() + uuid();
  const hash = bcrypt.hashSync(token, 10);
  const expiresAt = new Date(Date.now() + REFRESH_DAYS * 24 * 60 * 60 * 1000).toISOString();
  await run(
    "INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
    [uuid(), userId, hash, expiresAt, now()]
  );
  return { token, expiresAt };
}

async function verifyRefresh(userId, token) {
  const row = await get(
    "SELECT * FROM refresh_tokens WHERE user_id = ? AND revoked = 0 ORDER BY created_at DESC",
    [userId]
  );
  if (!row) return false;
  if (new Date(row.expires_at).getTime() < Date.now()) return false;
  return bcrypt.compareSync(token, row.token_hash);
}

async function revokeRefresh(userId) {
  await run("UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?", [userId]);
}

function authRequired(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing token" });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.sub;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

async function ensureMember(projectId, userId) {
  return await get("SELECT 1 FROM project_members WHERE project_id=? AND user_id=?", [projectId, userId]);
}

async function ensureCapability(projectId, userId, capability) {
  const row = await get("SELECT capabilities_json FROM project_members WHERE project_id=? AND user_id=?", [projectId, userId]);
  if (!row) return false;
  const caps = JSON.parse(row.capabilities_json || "[]");
  return caps.includes(capability);
}

const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
});

app.post("/auth/register", loginLimiter, async (req, res) => {
  const { email, password, displayName } = req.body || {};
  if (!email || !password || !displayName) return res.status(400).json({ error: "email, password, displayName required" });
  if (password.length < 6) return res.status(400).json({ error: "password min 6 chars" });
  const exists = await get("SELECT id FROM users WHERE lower(email)=lower(?)", [email]);
  if (exists) return res.status(400).json({ error: "email already exists" });
  const salt = bcrypt.genSaltSync(10);
  const hash = bcrypt.hashSync(password, salt);
  const id = uuid();
  await run(
    "INSERT INTO users (id, display_name, email, password_hash, password_salt, created_at) VALUES (?, ?, ?, ?, ?, ?)",
    [id, displayName, email, hash, salt, now()]
  );
  const accessToken = signAccess(id);
  const { token: refreshToken, expiresAt } = await issueRefresh(id);
  res.json({ accessToken, refreshToken, refreshExpiresAt: expiresAt, userId: id, displayName, email });
});

app.post("/auth/login", loginLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "email, password required" });
  const row = await get("SELECT * FROM users WHERE lower(email)=lower(?)", [email]);
  if (!row || !row.password_hash) return res.status(401).json({ error: "invalid credentials" });
  const ok = bcrypt.compareSync(password, row.password_hash);
  if (!ok) return res.status(401).json({ error: "invalid credentials" });
  const accessToken = signAccess(row.id);
  const { token: refreshToken, expiresAt } = await issueRefresh(row.id);
  res.json({ accessToken, refreshToken, refreshExpiresAt: expiresAt, userId: row.id, displayName: row.display_name, email: row.email });
});

app.post("/auth/refresh", loginLimiter, async (req, res) => {
  const { userId, refreshToken } = req.body || {};
  if (!userId || !refreshToken) return res.status(400).json({ error: "userId, refreshToken required" });
  const ok = await verifyRefresh(userId, refreshToken);
  if (!ok) return res.status(401).json({ error: "invalid refresh token" });
  const accessToken = signAccess(userId);
  res.json({ accessToken });
});

app.post("/auth/logout", authRequired, async (req, res) => {
  await revokeRefresh(req.userId);
  res.json({ ok: true });
});

app.get("/auth/me", authRequired, async (req, res) => {
  const user = await get("SELECT id, display_name, email FROM users WHERE id = ?", [req.userId]);
  if (!user) return res.status(404).json({ error: "user not found" });
  const projects = (await all(
    "SELECT p.id, p.name, pm.capabilities_json as capabilities FROM projects p JOIN project_members pm ON pm.project_id = p.id WHERE pm.user_id = ?",
    [req.userId]
  )).map((r) => ({ id: r.id, name: r.name, capabilities: JSON.parse(r.capabilities || "[]") }));
  res.json({ user, projects });
});

app.get("/projects", authRequired, async (req, res) => {
  const rows = await all(
    "SELECT p.id, p.name FROM projects p JOIN project_members pm ON pm.project_id = p.id WHERE pm.user_id = ? ORDER BY p.name ASC",
    [req.userId]
  );
  res.json(rows);
});

app.post("/projects", authRequired, async (req, res) => {
  const { name, capabilities = ["ADMIN_PROJECT", "WORK_TODAY", "EDIT_WORKITEM"] } = req.body || {};
  if (!name) return res.status(400).json({ error: "name required" });
  const id = uuid();
  const timestamp = now();
  await run("INSERT INTO projects (id, name, created_at, updated_at) VALUES (?, ?, ?, ?)", [
    id,
    name,
    timestamp,
    timestamp,
  ]);
  await run("INSERT INTO project_members (id, project_id, user_id, capabilities_json, created_at) VALUES (?, ?, ?, ?, ?)", [
    uuid(),
    id,
    req.userId,
    JSON.stringify(capabilities),
    timestamp,
  ]);
  res.json({ id, name });
});

app.get("/members", authRequired, async (req, res) => {
  const projectId = req.query.projectId;
  if (!projectId) return res.status(400).json({ error: "projectId required" });
  if (!(await ensureMember(projectId, req.userId))) return res.status(403).json({ error: "not a project member" });
  const rows = await all(
    "SELECT pm.id, pm.user_id as userId, u.display_name as displayName, u.email, pm.capabilities_json as capabilities FROM project_members pm JOIN users u ON u.id = pm.user_id WHERE pm.project_id = ?",
    [projectId]
  );
  res.json(rows.map((r) => ({ ...r, capabilities: JSON.parse(r.capabilities || "[]") })));
});

app.post("/members", authRequired, async (req, res) => {
  const { projectId, userId, capabilities = ["WORK_TODAY"] } = req.body || {};
  if (!projectId || !userId) return res.status(400).json({ error: "projectId, userId required" });
  if (!(await ensureCapability(projectId, req.userId, "ADMIN_PROJECT"))) return res.status(403).json({ error: "requires ADMIN_PROJECT" });
  const id = uuid();
  await run("INSERT INTO project_members (id, project_id, user_id, capabilities_json, created_at) VALUES (?, ?, ?, ?, ?)", [
    id,
    projectId,
    userId,
    JSON.stringify(capabilities),
    now(),
  ]);
  res.json({ id });
});

app.post("/sync/pull", authRequired, async (req, res) => {
  const { projectId, since } = req.body || {};
  if (!projectId) return res.status(400).json({ error: "projectId required" });
  if (!(await ensureMember(projectId, req.userId))) return res.status(403).json({ error: "not a project member" });
  const tasks = await all(
    `SELECT * FROM task_instances WHERE project_id = ? AND visibility IN ('SUBMITTED','PUBLIC') ${
      since ? "AND updated_at >= ?" : ""
    }`,
    [projectId].concat(since ? [since] : [])
  );
  const evidence = await all(
    `SELECT * FROM evidence WHERE project_id = ? AND visibility IN ('SUBMITTED','PUBLIC') ${
      since ? "AND created_at >= ?" : ""
    }`,
    [projectId].concat(since ? [since] : [])
  );
  res.json({ tasks, evidence });
});

app.post("/sync/push", authRequired, async (req, res) => {
  const { tasks = [], evidence = [] } = req.body || {};
  const upsertTask = async (t) => {
    await run(
      `INSERT INTO task_instances (id, project_id, work_item_id, owner_user_id, date, title, step_key, estimate_min, state, start_at, end_at, time_spent_sec, done_summary, blockers, visibility, submitted_at, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET
         project_id=excluded.project_id, work_item_id=excluded.work_item_id, owner_user_id=excluded.owner_user_id, date=excluded.date,
         title=excluded.title, step_key=excluded.step_key, estimate_min=excluded.estimate_min, state=excluded.state,
         start_at=excluded.start_at, end_at=excluded.end_at, time_spent_sec=excluded.time_spent_sec, done_summary=excluded.done_summary,
         blockers=excluded.blockers, visibility=excluded.visibility, submitted_at=excluded.submitted_at, updated_at=excluded.updated_at`,
      [
        t.id,
        t.project_id,
        t.work_item_id,
        t.owner_user_id,
        t.date,
        t.title,
        t.step_key,
        t.estimate_min,
        t.state,
        t.start_at,
        t.end_at,
        t.time_spent_sec,
        t.done_summary,
        t.blockers,
        t.visibility ?? "SUBMITTED",
        t.submitted_at ?? null,
        t.created_at,
        t.updated_at,
      ]
    );
  };
  const upsertEvidence = async (e) => {
    await run(
      `INSERT INTO evidence (id, project_id, task_instance_id, type, uri, meta_json, is_keyframe, visibility, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET
         project_id=excluded.project_id, task_instance_id=excluded.task_instance_id, type=excluded.type, uri=excluded.uri,
         meta_json=excluded.meta_json, is_keyframe=excluded.is_keyframe, visibility=excluded.visibility, created_at=excluded.created_at`,
      [
        e.id,
        e.project_id,
        e.task_instance_id,
        e.type,
        e.uri,
        typeof e.meta_json === "string" ? e.meta_json : JSON.stringify(e.meta_json || {}),
        e.is_keyframe ?? 0,
        e.visibility ?? "SUBMITTED",
        e.created_at,
      ]
    );
  };
  await transaction(async (db) => {
    for (const t of tasks) {
      if (await ensureMember(t.project_id, req.userId)) await upsertTask(t);
    }
    for (const e of evidence) {
      if (await ensureMember(e.project_id, req.userId)) await upsertEvidence(e);
    }
  });
  res.json({ ok: true });
});

app.post("/evidence/upload", authRequired, upload.single("file"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "file required" });
  // Serve via /uploads/:filename
  const uri = `/uploads/${req.file.filename}`;
  res.json({ uri, originalName: req.file.originalname });
});

app.get("/health", (_req, res) => res.json({ status: "ok", db: getDbInfo() }));
app.get("/", (_req, res) => res.json({ status: "ok" }));

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Nexus backend listening on http://localhost:${PORT}`);
});

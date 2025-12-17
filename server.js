#!/usr/bin/env node
import express from "express";
import cors from "cors";
import multer from "multer";
import Database from "better-sqlite3";
import { v4 as uuid } from "uuid";
import fs from "fs";
import path from "path";

const app = express();
app.use(cors());
app.use(express.json({ limit: "10mb" }));

function ensurePath(targetPath, fallbackDir, fallbackName) {
  if (targetPath) {
    try {
      fs.mkdirSync(path.dirname(targetPath), { recursive: true });
      return targetPath;
    } catch (e) {
      console.warn(`Cannot use ${targetPath}, fallback to local: ${e.message}`);
    }
  }
  const base = path.join(process.cwd(), fallbackDir);
  fs.mkdirSync(base, { recursive: true });
  return fallbackName ? path.join(base, fallbackName) : base;
}

const DB_PATH = ensurePath(process.env.NEXUS_DB, "data", "nexus.db");
const db = new Database(DB_PATH);

// Storage for evidence uploads
const uploadDir = ensurePath(process.env.UPLOAD_DIR, "uploads");
const upload = multer({ dest: uploadDir });

function migrate() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, display_name TEXT NOT NULL, email TEXT, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS projects (id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS project_members (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, user_id TEXT NOT NULL, capabilities_json TEXT NOT NULL, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS work_items (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, type TEXT NOT NULL, title TEXT NOT NULL, description TEXT, current_step TEXT NOT NULL, status TEXT NOT NULL, external_link TEXT, created_by_user_id TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS task_instances (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, work_item_id TEXT NOT NULL, owner_user_id TEXT NOT NULL, date TEXT NOT NULL, title TEXT NOT NULL, step_key TEXT NOT NULL, estimate_min INTEGER, state TEXT NOT NULL, start_at TEXT, end_at TEXT, time_spent_sec INTEGER DEFAULT 0, done_summary TEXT, blockers TEXT, visibility TEXT NOT NULL DEFAULT 'PRIVATE', submitted_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS evidence (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, task_instance_id TEXT NOT NULL, type TEXT NOT NULL, uri TEXT NOT NULL, meta_json TEXT NOT NULL, is_keyframe INTEGER NOT NULL DEFAULT 0, visibility TEXT NOT NULL DEFAULT 'PRIVATE', created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS artifacts (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, work_item_id TEXT NOT NULL, step_key TEXT NOT NULL, type TEXT NOT NULL, value_type TEXT NOT NULL, value TEXT NOT NULL, visibility TEXT NOT NULL DEFAULT 'PUBLIC', created_by_user_id TEXT NOT NULL, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS compliance_records (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, work_item_id TEXT NOT NULL, step_key TEXT NOT NULL, status TEXT NOT NULL, missing_artifacts_json TEXT NOT NULL, notes TEXT, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS task_reviews (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, task_instance_id TEXT NOT NULL, reviewer_user_id TEXT NOT NULL, action TEXT NOT NULL, note TEXT, from_visibility TEXT, to_visibility TEXT, created_at TEXT NOT NULL);
  `);
}

migrate();

function now() {
  return new Date().toISOString();
}

// Auth mock: email login returns user + token
app.post("/auth/login", (req, res) => {
  const { email, name } = req.body || {};
  if (!email && !name) return res.status(400).json({ error: "email or name required" });
  const display = name || email.split("@")[0];
  const userId = findOrCreateUser(display, email);
  const token = userId; // mock token = userId
  res.json({ token, userId, displayName: display });
});

function findOrCreateUser(displayName, email) {
  const row = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
  if (row) return row.id;
  const id = uuid();
  db.prepare("INSERT INTO users (id, display_name, email, created_at) VALUES (?, ?, ?, ?)").run(id, displayName, email, now());
  return id;
}

app.get("/projects", (req, res) => {
  const userId = req.headers["x-user-id"];
  if (!userId) return res.status(401).json({ error: "x-user-id required" });
  const rows = db
    .prepare(
      "SELECT p.id, p.name FROM projects p JOIN project_members pm ON pm.project_id = p.id WHERE pm.user_id = ? ORDER BY p.name ASC"
    )
    .all(userId);
  res.json(rows);
});

app.post("/projects", (req, res) => {
  const { name, userId, capabilities = ["ADMIN_PROJECT", "WORK_TODAY", "EDIT_WORKITEM"] } = req.body || {};
  if (!name || !userId) return res.status(400).json({ error: "name, userId required" });
  const id = uuid();
  const timestamp = now();
  db.prepare("INSERT INTO projects (id, name, created_at, updated_at) VALUES (?, ?, ?, ?)").run(id, name, timestamp, timestamp);
  db.prepare("INSERT INTO project_members (id, project_id, user_id, capabilities_json, created_at) VALUES (?, ?, ?, ?, ?)").run(
    uuid(),
    id,
    userId,
    JSON.stringify(capabilities),
    timestamp
  );
  res.json({ id, name });
});

app.get("/members", (req, res) => {
  const projectId = req.query.projectId;
  if (!projectId) return res.status(400).json({ error: "projectId required" });
  const rows = db
    .prepare(
      "SELECT pm.id, pm.user_id as userId, u.display_name as displayName, u.email, pm.capabilities_json as capabilities FROM project_members pm JOIN users u ON u.id = pm.user_id WHERE pm.project_id = ?"
    )
    .all(projectId)
    .map((r) => ({ ...r, capabilities: JSON.parse(r.capabilities || "[]") }));
  res.json(rows);
});

app.post("/members", (req, res) => {
  const { projectId, userId, capabilities = ["WORK_TODAY"] } = req.body || {};
  if (!projectId || !userId) return res.status(400).json({ error: "projectId, userId required" });
  const id = uuid();
  db.prepare("INSERT INTO project_members (id, project_id, user_id, capabilities_json, created_at) VALUES (?, ?, ?, ?, ?)").run(
    id,
    projectId,
    userId,
    JSON.stringify(capabilities),
    now()
  );
  res.json({ id });
});

// Sync endpoints (minimal)
app.post("/sync/pull", (req, res) => {
  const { projectId, since } = req.body || {};
  if (!projectId) return res.status(400).json({ error: "projectId required" });
  const tasks = db
    .prepare(
      `SELECT * FROM task_instances WHERE project_id = ? AND visibility IN ('SUBMITTED','PUBLIC') ${
        since ? "AND updated_at >= ?" : ""
      }`
    )
    .all(...([projectId].concat(since ? [since] : [])));
  const evidence = db
    .prepare(
      `SELECT * FROM evidence WHERE project_id = ? AND visibility IN ('SUBMITTED','PUBLIC') ${
        since ? "AND created_at >= ?" : ""
      }`
    )
    .all(...([projectId].concat(since ? [since] : [])));
  res.json({ tasks, evidence });
});

app.post("/sync/push", (req, res) => {
  const { tasks = [], evidence = [] } = req.body || {};
  const upsertTask = db.prepare(
    `INSERT INTO task_instances (id, project_id, work_item_id, owner_user_id, date, title, step_key, estimate_min, state, start_at, end_at, time_spent_sec, done_summary, blockers, visibility, submitted_at, created_at, updated_at)
     VALUES (@id,@project_id,@work_item_id,@owner_user_id,@date,@title,@step_key,@estimate_min,@state,@start_at,@end_at,@time_spent_sec,@done_summary,@blockers,@visibility,@submitted_at,@created_at,@updated_at)
     ON CONFLICT(id) DO UPDATE SET
       project_id=excluded.project_id, work_item_id=excluded.work_item_id, owner_user_id=excluded.owner_user_id, date=excluded.date,
       title=excluded.title, step_key=excluded.step_key, estimate_min=excluded.estimate_min, state=excluded.state,
       start_at=excluded.start_at, end_at=excluded.end_at, time_spent_sec=excluded.time_spent_sec, done_summary=excluded.done_summary,
       blockers=excluded.blockers, visibility=excluded.visibility, submitted_at=excluded.submitted_at, updated_at=excluded.updated_at`
  );
  const upsertEvidence = db.prepare(
    `INSERT INTO evidence (id, project_id, task_instance_id, type, uri, meta_json, is_keyframe, visibility, created_at)
     VALUES (@id,@project_id,@task_instance_id,@type,@uri,@meta_json,@is_keyframe,@visibility,@created_at)
     ON CONFLICT(id) DO UPDATE SET
       project_id=excluded.project_id, task_instance_id=excluded.task_instance_id, type=excluded.type, uri=excluded.uri,
       meta_json=excluded.meta_json, is_keyframe=excluded.is_keyframe, visibility=excluded.visibility, created_at=excluded.created_at`
  );
  const tx = db.transaction(() => {
    tasks.forEach((t) => upsertTask.run(t));
    evidence.forEach((e) => upsertEvidence.run({ ...e, meta_json: JSON.stringify(e.meta_json || {}) }));
  });
  tx();
  res.json({ ok: true });
});

// Evidence upload (returns URI)
app.post("/evidence/upload", upload.single("file"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "file required" });
  const uri = req.file.path;
  res.json({ uri });
});

app.get("/health", (_req, res) => res.json({ status: "ok", db: DB_PATH }));
app.get("/", (_req, res) => res.json({ status: "ok" }));

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Nexus backend listening on http://localhost:${PORT}`);
});

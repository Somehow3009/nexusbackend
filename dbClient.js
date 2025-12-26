import Database from "better-sqlite3";
import pg from "pg";
import fs from "fs";
import path from "path";

const usePg = !!process.env.DATABASE_URL;
const isSqlite = !usePg;

let sqliteDb = null;
let pgPool = null;

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

export function initDb(sqlitePath) {
  if (usePg) {
    pgPool = new pg.Pool({ connectionString: process.env.DATABASE_URL, max: 5 });
  } else {
    const dbPath = ensurePath(sqlitePath, "data", "nexus.db");
    sqliteDb = new Database(dbPath);
  }
}

export async function run(query, params = []) {
  if (usePg) {
    await pgPool.query(query, params);
  } else {
    sqliteDb.prepare(query).run(params);
  }
}

export async function all(query, params = []) {
  if (usePg) {
    const res = await pgPool.query(query, params);
    return res.rows;
  } else {
    return sqliteDb.prepare(query).all(params);
  }
}

export async function get(query, params = []) {
  if (usePg) {
    const res = await pgPool.query(query, params);
    return res.rows[0] || null;
  } else {
    return sqliteDb.prepare(query).get(params) || null;
  }
}

export async function transaction(fn) {
  if (usePg) {
    const client = await pgPool.connect();
    try {
      await client.query("BEGIN");
      await fn({
        run: (q, p = []) => client.query(q, p),
        all: (q, p = []) => client.query(q, p).then((r) => r.rows),
        get: (q, p = []) => client.query(q, p).then((r) => r.rows[0] || null),
      });
      await client.query("COMMIT");
    } catch (e) {
      await client.query("ROLLBACK");
      throw e;
    } finally {
      client.release();
    }
  } else {
    const tx = sqliteDb.transaction(fn);
    tx({
      run: (q, p = []) => sqliteDb.prepare(q).run(p),
      all: (q, p = []) => sqliteDb.prepare(q).all(p),
      get: (q, p = []) => sqliteDb.prepare(q).get(p) || null,
    });
  }
}

export function getDbInfo() {
  if (usePg) return { engine: "postgres", url: process.env.DATABASE_URL };
  return { engine: "sqlite", path: sqliteDb ? sqliteDb.name : "" };
}

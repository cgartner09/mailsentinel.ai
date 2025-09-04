// src/db.js
import Database from "better-sqlite3";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

// Use a persistent path if provided, else local ./data/
const DEFAULT_PATH = path.resolve(process.cwd(), "data", "mailsentinel.sqlite");
const DB_PATH = process.env.DB_PATH?.trim() || DEFAULT_PATH;

// Ensure the parent directory exists
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

// Open the database (create if missing)
const db = new Database(DB_PATH);

// Sensible pragmas
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

// --- Migrations (idempotent) ---
db.exec(`
  CREATE TABLE IF NOT EXISTS tenants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT UNIQUE NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'admin',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    key TEXT UNIQUE NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS quarantines (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id INTEGER NOT NULL,
    message_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    meta TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
  );
`);

export default db;
export { DB_PATH };

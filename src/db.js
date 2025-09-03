import Database from 'better-sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';
import { encrypt, decrypt } from './crypto.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const db = new Database(path.join(__dirname, '..', 'data', 'app.db'));
db.pragma('journal_mode = WAL');

export async function initDb() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      totp_secret TEXT,
      created_at INTEGER
    );

    CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY,
      external_id TEXT,
      source TEXT, -- gmail|outlook|upload
      from_addr TEXT,
      to_addr TEXT,
      subject TEXT,
      received_at INTEGER,
      verdict TEXT, -- clean|suspicious|malicious
      score REAL,
      quarantine INTEGER DEFAULT 0,
      encrypted_payload BLOB,
      created_at INTEGER
    );

    CREATE TABLE IF NOT EXISTS audits (
      id TEXT PRIMARY KEY,
      message_id TEXT,
      action TEXT, -- quarantine|release|delete|flag
      actor TEXT,
      note TEXT,
      created_at INTEGER
    );
  `);
}

export function resetDb() {
  db.exec(`DROP TABLE IF EXISTS users; DROP TABLE IF EXISTS messages; DROP TABLE IF EXISTS audits;`);
  return initDb().then(() => {
    console.log('Database reset.');
  });
}

// Helper to store message with encryption
export function insertMessage(m) {
  const now = Date.now();
  const payload = encrypt(JSON.stringify(m.raw || {}));
  const stmt = db.prepare(`
    INSERT INTO messages (id, external_id, source, from_addr, to_addr, subject, received_at, verdict, score, quarantine, encrypted_payload, created_at)
    VALUES (@id, @external_id, @source, @from_addr, @to_addr, @subject, @received_at, @verdict, @score, @quarantine, @encrypted_payload, @created_at)
  `);
  stmt.run({
    id: m.id,
    external_id: m.external_id || null,
    source: m.source || 'upload',
    from_addr: m.from_addr || '',
    to_addr: m.to_addr || '',
    subject: m.subject || '',
    received_at: m.received_at || now,
    verdict: m.verdict || 'suspicious',
    score: m.score ?? 0.5,
    quarantine: m.quarantine ? 1 : 0,
    encrypted_payload: payload,
    created_at: now
  });
}

export function getMessage(id) {
  const row = db.prepare(`SELECT * FROM messages WHERE id = ?`).get(id);
  if (!row) return null;
  const raw = JSON.parse(decrypt(row.encrypted_payload));
  return { ...row, raw };
}

export function listMessages({ quarantine = true } = {}) {
  const rows = db.prepare(`SELECT id, source, from_addr, to_addr, subject, received_at, verdict, score, quarantine FROM messages WHERE quarantine = ? ORDER BY received_at DESC LIMIT 500`).all(quarantine ? 1 : 0);
  return rows;
}

export function updateQuarantine(id, value) {
  db.prepare(`UPDATE messages SET quarantine = ? WHERE id = ?`).run(value ? 1 : 0, id);
}

export function insertAudit({ id, message_id, action, actor, note }) {
  db.prepare(`INSERT INTO audits (id, message_id, action, actor, note, created_at) VALUES (?, ?, ?, ?, ?, ?)`)
    .run(id, message_id, action, actor, note || '', Date.now());
}

import { db } from './db.js';
import bcrypt from 'bcryptjs';
import { nanoid } from 'nanoid';
import speakeasy from 'speakeasy';

export async function ensureAdmin() {
  const email = process.env.ADMIN_EMAIL;
  const pass = process.env.ADMIN_PASSWORD;
  if (!email || !pass) return;

  const row = db.prepare(`SELECT id FROM users WHERE email = ?`).get(email);
  if (!row) {
    const hash = await bcrypt.hash(pass, 12);
    db.prepare(`INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)`)
      .run(nanoid(), email, hash, Date.now());
    console.log(`Bootstrap admin created: ${email}`);
  }
}

export async function validateUser(email, password) {
  const row = db.prepare(`SELECT * FROM users WHERE email = ?`).get(email);
  if (!row) return null;
  const ok = await bcrypt.compare(password, row.password_hash);
  if (!ok) return null;
  return row;
}

export function setTotp(userId, secretBase32) {
  db.prepare(`UPDATE users SET totp_secret = ? WHERE id = ?`).run(secretBase32, userId);
}

export function verifyTotp(user, token) {
  if (!user.totp_secret) return false;
  return speakeasy.totp.verify({
    secret: user.totp_secret,
    encoding: 'base32',
    token,
    window: 1
  });
}

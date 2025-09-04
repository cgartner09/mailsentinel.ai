// src/server.js
import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import path from "node:path";
import fs from "node:fs";
import process from "node:process";
import crypto from "node:crypto";

import db, { DB_PATH } from "./db.js";
import argon2 from "argon2";
import jwt from "jsonwebtoken";

const app = express();

/* ------------------------ Core middleware ------------------------ */
app.use(helmet());
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.set("trust proxy", 1);

const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";
app.use(
  cors({
    origin: CORS_ORIGIN === "*" ? true : [CORS_ORIGIN],
    credentials: true,
  })
);

app.use(morgan("combined"));

/* ------------------------ Health & Ready ------------------------- */
app.get("/health", (req, res) => {
  try {
    const row = db.prepare("SELECT 1 AS ok").get();
    res.status(200).json({
      status: "ok",
      db: row?.ok === 1 ? "connected" : "unknown",
      dbPath: DB_PATH,
      time: new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({ status: "error", error: String(err) });
  }
});

app.get("/ready", (req, res) => {
  const required = ["SESSION_SECRET", "DATA_KEY_HEX"];
  const missing = required.filter((k) => !process.env[k]);
  if (missing.length) {
    return res.status(500).json({ status: "not-ready", missing });
  }
  return res
    .status(200)
    .json({ status: "ready", message: "All required env vars are set" });
});

/* ------------------------- Init Admin ---------------------------- */
/**
 * POST /init-admin
 * One-time seeding to create:
 *  - tenant from ADMIN_EMAIL's domain
 *  - admin user (ADMIN_EMAIL / ADMIN_PASSWORD)
 *  - default API key for that tenant
 *
 * Protection via secret:
 *  Header:  x-init-token: <INIT_TOKEN>  OR  Query: ?token=<INIT_TOKEN>
 */
app.post("/init-admin", async (req, res) => {
  try {
    const provided =
      req.header("x-init-token") || req.query.token || req.body?.token || "";

    const INIT_TOKEN = (process.env.INIT_TOKEN || "").trim();
    if (!INIT_TOKEN) {
      return res.status(500).json({ error: "INIT_TOKEN is not set in env" });
    }
    if (provided !== INIT_TOKEN) {
      return res.status(401).json({ error: "Unauthorized: invalid init token" });
    }

    const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
    const ADMIN_PASSWORD = (process.env.ADMIN_PASSWORD || "").trim();
    if (!ADMIN_EMAIL || !ADMIN_PASSWORD) {
      return res
        .status(400)
        .json({ error: "ADMIN_EMAIL and ADMIN_PASSWORD must be set" });
    }

    const domain = ADMIN_EMAIL.includes("@")
      ? ADMIN_EMAIL.split("@").pop()
      : null;
    if (!domain) return res.status(400).json({ error: "ADMIN_EMAIL is invalid" });

    const existingUser = db
      .prepare("SELECT id, tenant_id FROM users WHERE email = ?")
      .get(ADMIN_EMAIL);
    if (existingUser) {
      return res.status(200).json({
        status: "exists",
        message: "Admin user already present",
        userId: existingUser.id,
        tenantId: existingUser.tenant_id,
      });
    }

    // Upsert tenant
    let tenant = db.prepare("SELECT id FROM tenants WHERE domain = ?").get(domain);
    if (!tenant) {
      db.prepare("INSERT INTO tenants (domain) VALUES (?)").run(domain);
      tenant = db.prepare("SELECT id FROM tenants WHERE domain = ?").get(domain);
    }

    // Create admin user
    const password_hash = await argon2.hash(ADMIN_PASSWORD);
    const insertUser = db.prepare(
      `INSERT INTO users (tenant_id, email, password_hash, role) VALUES (?, ?, ?, 'admin')`
    );
    const result = insertUser.run(tenant.id, ADMIN_EMAIL, password_hash);

    // Default API key for tenant
    const apiKey = `msk_${crypto.randomBytes(24).toString("hex")}`;
    db.prepare(
      `INSERT INTO api_keys (tenant_id, name, key) VALUES (?, ?, ?)`
    ).run(tenant.id, "Default", apiKey);

    return res.status(201).json({
      status: "created",
      tenantId: tenant.id,
      userId: result.lastInsertRowid,
      apiKeyPreview: apiKey.slice(0, 8) + "…",
    });
  } catch (err) {
    console.error("init-admin error:", err);
    return res
      .status(500)
      .json({ error: "Failed to init admin", detail: String(err) });
  }
});

/* ---------------------------- Signup ----------------------------- */
/**
 * POST /signup
 * Body: { email, password, company?, plan? }
 * - Upserts tenant by email domain
 * - First user in a tenant becomes 'admin', others 'member'
 * - Hashes password with argon2
 * - Issues JWT -> HttpOnly cookie 'auth'
 */
app.post("/signup", async (req, res) => {
  try {
    const { email, password, company, plan } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: "email and password are required" });
    }
    const emailNorm = String(email).trim().toLowerCase();
    const passwordStr = String(password);

    if (!emailNorm.includes("@") || emailNorm.startsWith("@") || emailNorm.endsWith("@")) {
      return res.status(400).json({ error: "invalid email" });
    }
    const domain = emailNorm.split("@").pop();
    if (!domain) return res.status(400).json({ error: "invalid email domain" });

    // Duplicate check
    const existing = db.prepare("SELECT id FROM users WHERE email = ?").get(emailNorm);
    if (existing) return res.status(409).json({ error: "account already exists" });

    // Upsert tenant
    let tenant = db.prepare("SELECT id FROM tenants WHERE domain = ?").get(domain);
    if (!tenant) {
      db.prepare("INSERT INTO tenants (domain) VALUES (?)").run(domain);
      tenant = db.prepare("SELECT id FROM tenants WHERE domain = ?").get(domain);
    }

    // Role
    const userCount = db
      .prepare("SELECT COUNT(*) AS c FROM users WHERE tenant_id = ?")
      .get(tenant.id).c;
    const role = userCount === 0 ? "admin" : "member";

    // Create user
    const password_hash = await argon2.hash(passwordStr);
    const insertUser = db.prepare(
      `INSERT INTO users (tenant_id, email, password_hash, role) VALUES (?, ?, ?, ?)`
    );
    const result = insertUser.run(tenant.id, emailNorm, password_hash, role);

    // JWT
    const secret = process.env.SESSION_SECRET;
    if (!secret) return res.status(500).json({ error: "SESSION_SECRET not set" });
    const payload = {
      sub: String(result.lastInsertRowid),
      email: emailNorm,
      tenantId: tenant.id,
      role,
    };
    const token = jwt.sign(payload, secret, { expiresIn: "7d" });

    // Cookie
    const isProd = process.env.NODE_ENV === "production";
    res.cookie("auth", token, {
      httpOnly: true,
      secure: isProd,
      sameSite: "lax",
      path: "/",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.status(201).json({
      status: "created",
      tenantId: tenant.id,
      userId: result.lastInsertRowid,
      role,
      plan: plan || null,
      company: company || null,
      redirect: "/dashboard",
      tokenPreview: token.slice(0, 12) + "…", // for debug only
    });
  } catch (err) {
    console.error("signup error:", err);
    return res.status(500).json({ error: "Failed to sign up", detail: String(err) });
  }
});

// Simple HTML form to test POST /signup quickly in a browser
app.get("/signup", (req, res) => {
  res.type("html").send(`<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Signup</title></head>
<body style="font-family: sans-serif; padding: 24px;">
  <h1>MailSentinel.ai — Sign Up</h1>
  <form method="POST" action="/signup">
    <div><label>Email <input name="email" type="email" required></label></div>
    <div><label>Password <input name="password" type="password" required></label></div>
    <div><label>Company <input name="company" type="text"></label></div>
    <div><label>Plan
      <select name="plan">
        <option value="">(none)</option>
        <option value="starter">Starter ($10)</option>
        <option value="pro">Pro ($25)</option>
        <option value="business">Business ($299)</option>
      </select>
    </label></div>
    <button type="submit">Create account</button>
  </form>
</body>
</html>`);
});

/* ----------------------------- Login ----------------------------- */
/**
 * POST /login
 * Body: { email, password }
 * - Verifies user exists and password matches (argon2.verify)
 * - Issues JWT -> HttpOnly cookie 'auth'
 */
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: "email and password are required" });
    }

    const emailNorm = String(email).trim().toLowerCase();
    const user = db
      .prepare("SELECT id, tenant_id, email, password_hash, role FROM users WHERE email = ?")
      .get(emailNorm);

    if (!user) return res.status(401).json({ error: "invalid credentials" });

    const ok = await argon2.verify(user.password_hash, String(password));
    if (!ok) return res.status(401).json({ error: "invalid credentials" });

    const secret = process.env.SESSION_SECRET;
    if (!secret) return res.status(500).json({ error: "SESSION_SECRET not set" });

    const payload = {
      sub: String(user.id),
      email: user.email,
      tenantId: user.tenant_id,
      role: user.role,
    };
    const token = jwt.sign(payload, secret, { expiresIn: "7d" });

    const isProd = process.env.NODE_ENV === "production";
    res.cookie("auth", token, {
      httpOnly: true,
      secure: isProd,
      sameSite: "lax",
      path: "/",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.status(200).json({
      status: "ok",
      tenantId: user.tenant_id,
      userId: user.id,
      role: user.role,
      redirect: "/dashboard",
      tokenPreview: token.slice(0, 12) + "…", // for debug only
    });
  } catch (err) {
    console.error("login error:", err);
    return res.status(500).json({ error: "Failed to login", detail: String(err) });
  }
});

// Simple HTML form to test POST /login
app.get("/login", (req, res) => {
  res.type("html").send(`<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Login</title></head>
<body style="font-family: sans-serif; padding: 24px;">
  <h1>MailSentinel.ai — Login</h1>
  <form method="POST" action="/login">
    <div><label>Email <input name="email" type="email" required></label></div>
    <div><label>Password <input name="password" type="password" required></label></div>
    <button type="submit">Log in</button>
  </form>
</body>
</html>`);
});

/* ---------------------- Basic root + errors ---------------------- */
app.get("/", (req, res) => {
  res.type("text/plain").send("MailSentinel.ai backend is running");
});

app.use((req, res) => res.status(404).json({ error: "Not found" }));

app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ error: "Internal Server Error" });
});

/* -------------------------- Startup logs ------------------------- */
const PORT = Number(process.env.PORT || 3000);
const HOST = "0.0.0.0";

console.log("==== Boot Info ====");
console.log("NODE_ENV:", process.env.NODE_ENV);
console.log("PORT:", PORT);
console.log("CORS_ORIGIN:", CORS_ORIGIN);
console.log("APP_PUBLIC_URL:", process.env.APP_PUBLIC_URL || "(unset)");
console.log("DB_PATH:", DB_PATH);
try {
  const dir = path.dirname(DB_PATH);
  console.log("DB dir exists:", fs.existsSync(dir));
} catch (e) {
  console.log("DB dir check error:", e);
}

const server = app.listen(PORT, HOST, () => {
  console.log(`Server listening on http://${HOST}:${PORT}`);
});

process.on("unhandledRejection", (reason) => {
  console.error("Unhandled Rejection:", reason);
});
process.on("uncaughtException", (err) => {
  console.error("Uncaught Exception:", err);
});

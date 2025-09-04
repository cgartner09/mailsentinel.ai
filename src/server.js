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
import { v4 as uuidv4 } from "uuid";

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

// Liveness + tiny DB query
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

// Env readiness (add more required vars as you need)
app.get("/ready", (req, res) => {
  const required = [
    "SESSION_SECRET",
    "DATA_KEY_HEX",
    // Optional to enforce at startup:
    // "APP_PUBLIC_URL",
    // "CORS_ORIGIN",
  ];
  const missing = required.filter((k) => !process.env[k]);
  if (missing.length) {
    return res.status(500).json({ status: "not-ready", missing });
  }
  return res.status(200).json({ status: "ready", message: "All required env vars are set" });
});

/* ------------------------- Init Admin ---------------------------- */
/**
 * POST /init-admin
 * One-time seeding to create:
 *  - tenant from ADMIN_EMAIL's domain
 *  - admin user (ADMIN_EMAIL / ADMIN_PASSWORD)
 *  - default API key for that tenant
 *
 * Protection:
 *  - You must provide the secret token via:
 *      Header:  x-init-token: <INIT_TOKEN>
 *    or Query:  ?token=<INIT_TOKEN>
 *
 * Required env:
 *  - ADMIN_EMAIL
 *  - ADMIN_PASSWORD
 *  - INIT_TOKEN
 */
app.post("/init-admin", async (req, res) => {
  try {
    const provided =
      req.header("x-init-token") || req.query.token || req.body?.token || "";

    const INIT_TOKEN = (process.env.INIT_TOKEN || "").trim();
    if (!INIT_TOKEN) {
      return res.status(500).json({
        error: "INIT_TOKEN is not set in environment. Refusing to run.",
      });
    }
    if (provided !== INIT_TOKEN) {
      return res.status(401).json({ error: "Unauthorized: invalid init token" });
    }

    const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
    const ADMIN_PASSWORD = (process.env.ADMIN_PASSWORD || "").trim();

    if (!ADMIN_EMAIL || !ADMIN_PASSWORD) {
      return res.status(400).json({
        error: "ADMIN_EMAIL and ADMIN_PASSWORD must be set in environment",
      });
    }

    // simple email/domain extraction
    const domain = ADMIN_EMAIL.includes("@")
      ? ADMIN_EMAIL.split("@").pop()
      : null;

    if (!domain) {
      return res.status(400).json({ error: "ADMIN_EMAIL is not a valid email" });
    }

    // If user already exists, return idempotent success
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

    // Upsert tenant by domain
    let tenant = db.prepare("SELECT id FROM tenants WHERE domain = ?").get(domain);
    if (!tenant) {
      db.prepare("INSERT INTO tenants (domain) VALUES (?)").run(domain);
      tenant = db.prepare("SELECT id FROM tenants WHERE domain = ?").get(domain);
    }

    // Create admin user
    const password_hash = await argon2.hash(ADMIN_PASSWORD);
    const insertUser = db.prepare(`
      INSERT INTO users (tenant_id, email, password_hash, role)
      VALUES (?, ?, ?, 'admin')
    `);
    const result = insertUser.run(tenant.id, ADMIN_EMAIL, password_hash);

    // Create a default API key for the tenant
    const apiKey = `msk_${crypto.randomBytes(24).toString("hex")}`;
    db.prepare(
      `INSERT INTO api_keys (tenant_id, name, key) VALUES (?, ?, ?)`
    ).run(tenant.id, "Default", apiKey);

    return res.status(201).json({
      status: "created",
      tenantId: tenant.id,
      userId: result.lastInsertRowid,
      apiKeyPreview: apiKey.slice(0, 8) + "…", // don't dump full secret in logs
    });
  } catch (err) {
    console.error("init-admin error:", err);
    return res.status(500).json({ error: "Failed to init admin", detail: String(err) });
  }
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

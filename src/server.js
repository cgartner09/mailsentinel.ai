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

// set cookie helpers without adding cookie-parser
function setAuthCookie(res, token) {
  const isProd = process.env.NODE_ENV === "production";
  res.cookie("auth", token, {
    httpOnly: true,
    secure: isProd,
    sameSite: "lax",
    path: "/",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
}
function clearAuthCookie(res) {
  const isProd = process.env.NODE_ENV === "production";
  res.cookie("auth", "", {
    httpOnly: true,
    secure: isProd,
    sameSite: "lax",
    path: "/",
    maxAge: 0,
  });
}

const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";
app.use(
  cors({
    origin: CORS_ORIGIN === "*" ? true : [CORS_ORIGIN],
    credentials: true,
  })
);
app.use(morgan("combined"));

/* ----------------------- Brand + template ------------------------ */
const BRAND = { name: "MailSentinel.ai", primary: "#0ea5e9", accent: "#22c55e" };
const envelopeLogoSVG = (size = 32) => `
<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 512 512" fill="none" aria-hidden="true">
  <rect width="512" height="512" rx="100" fill="#0f172a"/>
  <defs>
    <linearGradient id="grad1" x1="40" y1="120" x2="472" y2="392" gradientUnits="userSpaceOnUse">
      <stop offset="0%" stop-color="${BRAND.primary}"/>
      <stop offset="100%" stop-color="${BRAND.accent}"/>
    </linearGradient>
  </defs>
  <path d="M60 120h392c11 0 20 9 20 20v232c0 11-9 20-20 20H60c-11 0-20-9-20-20V140c0-11 9-20 20-20z"
    stroke="url(#grad1)" stroke-width="32" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
  <path d="M40 140l216 160 216-160" stroke="url(#grad1)" stroke-width="32" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
</svg>`;
const pageTemplate = ({ title, body }) => `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>${title} — MailSentinel.ai</title>
<meta name="theme-color" content="#0f172a"/><script src="https://cdn.tailwindcss.com"></script>
<style>:root{--brand:${BRAND.primary};--accent:${BRAND.accent}}.btn-brand{background:var(--brand);color:#fff}.btn-brand:hover{filter:brightness(1.05)}.link-brand{color:var(--brand)}</style>
</head>
<body class="min-h-screen bg-slate-900 text-white">
<header class="sticky top-0 z-40 backdrop-blur bg-slate-900/80 border-b border-slate-800">
  <nav class="max-w-5xl mx-auto px-4 py-4 flex items-center justify-between">
    <a href="/" class="flex items-center gap-3">${envelopeLogoSVG(36)}<span class="font-extrabold text-2xl">MailSentinel.ai</span></a>
    <div class="hidden sm:flex items-center gap-6 text-sm">
      <a href="https://mailsentinel.ai/#features" class="text-gray-300 hover:text-white">Features</a>
      <a href="https://mailsentinel.ai/#pricing" class="text-gray-300 hover:text-white">Pricing</a>
      <a href="https://mailsentinel.ai/#contact" class="text-gray-300 hover:text-white">Contact</a>
    </div>
  </nav>
</header>
<main class="max-w-5xl mx-auto px-4 py-10">${body}</main>
<footer class="border-t border-slate-800 mt-10">
  <div class="max-w-5xl mx-auto px-4 py-6 text-sm text-gray-400">© ${new Date().getFullYear()} MailSentinel.ai. All rights reserved.</div>
</footer>
</body></html>`;

/* ---------------------- Health & readiness ----------------------- */
import { DB_PATH as _db_path } from "./db.js";
const DBPATH = _db_path;

app.get("/health", (req, res) => {
  try {
    const row = db.prepare("SELECT 1 AS ok").get();
    res.status(200).json({ status: "ok", db: row?.ok === 1 ? "connected" : "unknown", dbPath: DBPATH, time: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ status: "error", error: String(err) });
  }
});
app.get("/ready", (req, res) => {
  const required = ["SESSION_SECRET", "DATA_KEY_HEX"];
  const missing = required.filter((k) => !process.env[k]);
  if (missing.length) return res.status(500).json({ status: "not-ready", missing });
  res.status(200).json({ status: "ready", message: "All required env vars are set" });
});

/* -------------------------- Init admin --------------------------- */
app.post("/init-admin", async (req, res) => {
  try {
    const provided = req.header("x-init-token") || req.query.token || req.body?.token || "";
    const INIT_TOKEN = (process.env.INIT_TOKEN || "").trim();
    if (!INIT_TOKEN) return res.status(500).json({ error: "INIT_TOKEN is not set in env" });
    if (provided !== INIT_TOKEN) return res.status(401).json({ error: "Unauthorized: invalid init token" });

    const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
    const ADMIN_PASSWORD = (process.env.ADMIN_PASSWORD || "").trim();
    if (!ADMIN_EMAIL || !ADMIN_PASSWORD) return res.status(400).json({ error: "ADMIN_EMAIL and ADMIN_PASSWORD must be set" });

    const domain = ADMIN_EMAIL.includes("@") ? ADMIN_EMAIL.split("@").pop() : null;
    if (!domain) return res.status(400).json({ error: "ADMIN_EMAIL is invalid" });

    const existingUser = db.prepare("SELECT id, tenant_id FROM users WHERE email = ?").get(ADMIN_EMAIL);
    if (existingUser) return res.status(200).json({ status: "exists", userId: existingUser.id, tenantId: existingUser.tenant_id });

    let tenant = db.prepare("SELECT id FROM tenants WHERE domain = ?").get(domain);
    if (!tenant) {
      db.prepare("INSERT INTO tenants (domain) VALUES (?)").run(domain);
      tenant = db.prepare("SELECT id FROM tenants WHERE domain = ?").get(domain);
    }

    const password_hash = await argon2.hash(ADMIN_PASSWORD);
    const result = db.prepare(`INSERT INTO users (tenant_id, email, password_hash, role) VALUES (?, ?, ?, 'admin')`)
      .run(tenant.id, ADMIN_EMAIL, password_hash);

    const apiKey = `msk_${crypto.randomBytes(24).toString("hex")}`;
    db.prepare(`INSERT INTO api_keys (tenant_id, name, key) VALUES (?, ?, ?)`).run(tenant.id, "Default", apiKey);

    res.status(201).json({ status: "created", tenantId: tenant.id, userId: result.lastInsertRowid, apiKeyPreview: apiKey.slice(0, 8) + "…" });
  } catch (err) {
    console.error("init-admin error:", err);
    res.status(500).json({ error: "Failed to init admin", detail: String(err) });
  }
});

/* --------------------------- Auth utils -------------------------- */
function signJWT(payload) {
  const secret = process.env.SESSION_SECRET;
  if (!secret) throw new Error("SESSION_SECRET not set");
  return jwt.sign(payload, secret, { expiresIn: "7d" });
}
function verifyJWT(token) {
  const secret = process.env.SESSION_SECRET;
  return jwt.verify(token, secret);
}
function readAuthToken(req) {
  const cookieHeader = req.headers.cookie || "";
  const match = cookieHeader.match(/(?:^|;\s*)auth=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : null;
}
function requireAuth(req, res, next) {
  try {
    const token = readAuthToken(req) || (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
    if (!token) return res.status(401).json({ error: "unauthorized" });
    const payload = verifyJWT(token);
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ error: "unauthorized" });
  }
}

/* ----------------------------- Signup ---------------------------- */
app.post("/signup", async (req, res) => {
  try {
    const { email, password, company, plan } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: "email and password are required" });
    const emailNorm = String(email).trim().toLowerCase();
    if (!emailNorm.includes("@") || emailNorm.startsWith("@") || emailNorm.endsWith("@")) return res.status(400).json({ error: "invalid email" });
    const domain = emailNorm.split("@").pop();
    if (!domain) return res.status(400).json({ error: "invalid email domain" });

    const existing = db.prepare("SELECT id FROM users WHERE email = ?").get(emailNorm);
    if (existing) return res.status(409).json({ error: "account already exists" });

    let tenant = db.prepare("SELECT id FROM tenants WHERE domain = ?").get(domain);
    if (!tenant) {
      db.prepare("INSERT INTO tenants (domain) VALUES (?)").run(domain);
      tenant = db.prepare("SELECT id FROM tenants WHERE domain = ?").get(domain);
    }

    const count = db.prepare("SELECT COUNT(*) AS c FROM users WHERE tenant_id = ?").get(tenant.id).c;
    const role = count === 0 ? "admin" : "member";

    const password_hash = await argon2.hash(String(password));
    const result = db.prepare(`INSERT INTO users (tenant_id, email, password_hash, role) VALUES (?, ?, ?, ?)`)
      .run(tenant.id, emailNorm, password_hash, role);

    const token = signJWT({ sub: String(result.lastInsertRowid), email: emailNorm, tenantId: tenant.id, role });
    setAuthCookie(res, token);

    res.status(201).json({ status: "created", tenantId: tenant.id, userId: result.lastInsertRowid, role, plan: plan || null, company: company || null, redirect: "/dashboard", tokenPreview: token.slice(0, 12) + "…" });
  } catch (err) {
    console.error("signup error:", err);
    res.status(500).json({ error: "Failed to sign up", detail: String(err) });
  }
});
app.get("/signup", (req, res) => {
  const body = `
  <section class="relative">
    <div class="absolute -top-24 -right-24 w-[28rem] h-[28rem] rounded-full blur-3xl opacity-20" style="background:${BRAND.primary}"></div>
    <div class="absolute -bottom-24 -left-24 w-[28rem] h-[28rem] rounded-full blur-3xl opacity-20" style="background:${BRAND.accent}"></div>
    <div class="max-w-xl mx-auto mt-6">
      <h1 class="text-3xl md:text-4xl font-extrabold">Create your account</h1>
      <p class="mt-2 text-gray-300">Start your 14-day free trial. No credit card required.</p>
      <form method="POST" action="/signup" class="mt-6 bg-slate-800 border border-slate-700 rounded-2xl p-6 space-y-4 shadow">
        <div><label class="text-sm font-medium">Email</label><input name="email" type="email" required class="mt-1 w-full rounded-xl border border-slate-600 bg-slate-900 px-3 py-2 text-white" placeholder="you@company.com"/></div>
        <div><label class="text-sm font-medium">Password</label><input name="password" type="password" required class="mt-1 w-full rounded-xl border border-slate-600 bg-slate-900 px-3 py-2 text-white" placeholder="••••••••"/></div>
        <div><label class="text-sm font-medium">Company</label><input name="company" class="mt-1 w-full rounded-xl border border-slate-600 bg-slate-900 px-3 py-2 text-white" placeholder="Company LLC"/></div>
        <div><label class="text-sm font-medium">Plan</label><select name="plan" class="mt-1 w-full rounded-xl border border-slate-600 bg-slate-900 px-3 py-2 text-white"><option value="">(none)</option><option value="starter">Starter ($10 / 3 inboxes)</option><option value="pro">Pro ($25 / 50 mailboxes)</option><option value="business">Business ($299)</option></select></div>
        <button type="submit" class="w-full btn-brand rounded-2xl px-4 py-3 font-semibold">Sign Up</button>
        <p class="text-center text-sm text-gray-400">Already have an account? <a href="/login" class="link-brand hover:underline">Log in</a></p>
      </form>
    </div>
  </section>`;
  res.type("html").send(pageTemplate({ title: "Sign Up", body }));
});

/* ----------------------------- Login ----------------------------- */
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: "email and password are required" });

    const emailNorm = String(email).trim().toLowerCase();
    const user = db.prepare("SELECT id, tenant_id, email, password_hash, role FROM users WHERE email = ?").get(emailNorm);
    if (!user) return res.status(401).json({ error: "invalid credentials" });

    const ok = await argon2.verify(user.password_hash, String(password));
    if (!ok) return res.status(401).json({ error: "invalid credentials" });

    const token = signJWT({ sub: String(user.id), email: user.email, tenantId: user.tenant_id, role: user.role });
    setAuthCookie(res, token);

    res.status(200).json({ status: "ok", tenantId: user.tenant_id, userId: user.id, role: user.role, redirect: "/dashboard", tokenPreview: token.slice(0, 12) + "…" });
  } catch (err) {
    console.error("login error:", err);
    res.status(500).json({ error: "Failed to login", detail: String(err) });
  }
});
app.get("/login", (req, res) => {
  const body = `
  <section class="relative">
    <div class="absolute -top-24 -right-24 w-[28rem] h-[28rem] rounded-full blur-3xl opacity-20" style="background:${BRAND.primary}"></div>
    <div class="absolute -bottom-24 -left-24 w-[28rem] h-[28rem] rounded-full blur-3xl opacity-20" style="background:${BRAND.accent}"></div>
    <div class="max-w-xl mx-auto mt-6">
      <h1 class="text-3xl md:text-4xl font-extrabold">Welcome back</h1>
      <p class="mt-2 text-gray-300">Log in to manage quarantine, alerts, and settings.</p>
      <form method="POST" action="/login" class="mt-6 bg-slate-800 border border-slate-700 rounded-2xl p-6 space-y-4 shadow">
        <div><label class="text-sm font-medium">Email</label><input name="email" type="email" required class="mt-1 w-full rounded-xl border border-slate-600 bg-slate-900 px-3 py-2 text-white" placeholder="you@company.com"/></div>
        <div><label class="text-sm font-medium">Password</label><input name="password" type="password" required class="mt-1 w-full rounded-xl border border-slate-600 bg-slate-900 px-3 py-2 text-white" placeholder="••••••••"/></div>
        <button type="submit" class="w-full btn-brand rounded-2xl px-4 py-3 font-semibold">Log In</button>
        <p class="text-center text-sm text-gray-400">New here? <a href="/signup" class="link-brand hover:underline">Create an account</a></p>
      </form>
    </div>
  </section>`;
  res.type("html").send(pageTemplate({ title: "Login", body }));
});

/* ----------------------- Protected endpoints --------------------- */
app.get("/me", requireAuth, (req, res) => {
  res.json({ user: req.user });
});

app.post("/logout", (req, res) => {
  clearAuthCookie(res);
  res.json({ status: "ok" });
});

app.get("/dashboard", requireAuth, (req, res) => {
  const body = `
  <section class="relative">
    <div class="absolute -top-24 -right-24 w-[28rem] h-[28rem] rounded-full blur-3xl opacity-20" style="background:${BRAND.primary}"></div>
    <div class="absolute -bottom-24 -left-24 w-[28rem] h-[28rem] rounded-full blur-3xl opacity-20" style="background:${BRAND.accent}"></div>
    <div class="max-w-3xl mx-auto mt-6">
      <h1 class="text-3xl md:text-4xl font-extrabold">Dashboard</h1>
      <p class="mt-2 text-gray-300">Welcome, <span class="font-semibold">${req.user.email}</span>.</p>
      <div class="mt-6 grid sm:grid-cols-2 gap-4">
        <div class="rounded-2xl border border-slate-700 bg-slate-800 p-6">
          <h3 class="text-lg font-semibold">Tenant</h3>
          <p class="text-gray-300 mt-1">ID: ${req.user.tenantId}</p>
          <p class="text-gray-300">Role: ${req.user.role}</p>
        </div>
        <div class="rounded-2xl border border-slate-700 bg-slate-800 p-6">
          <h3 class="text-lg font-semibold">Quick actions</h3>
          <div class="mt-3 flex gap-3">
            <form method="POST" action="/logout"><button class="btn-brand rounded-xl px-4 py-2">Log out</button></form>
          </div>
        </div>
      </div>
    </div>
  </section>`;
  res.type("html").send(pageTemplate({ title: "Dashboard", body }));
});

/* ---------------------- Root, errors, startup -------------------- */
app.get("/", (req, res) => {
  res.type("text/plain").send("MailSentinel.ai backend is running");
});
app.use((req, res) => res.status(404).json({ error: "Not found" }));
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ error: "Internal Server Error" });
});

const PORT = Number(process.env.PORT || 3000);
const HOST = "0.0.0.0";
console.log("==== Boot Info ====");
console.log("NODE_ENV:", process.env.NODE_ENV);
console.log("PORT:", PORT);
console.log("CORS_ORIGIN:", CORS_ORIGIN);
console.log("APP_PUBLIC_URL:", process.env.APP_PUBLIC_URL || "(unset)");
console.log("DB_PATH:", DBPATH);
try {
  const dir = path.dirname(DBPATH);
  console.log("DB dir exists:", fs.existsSync(dir));
} catch (e) {
  console.log("DB dir check error:", e);
}
app.listen(PORT, HOST, () => console.log(`Server listening on http://${HOST}:${PORT}`));
process.on("unhandledRejection", (r) => console.error("Unhandled Rejection:", r));
process.on("uncaughtException", (e) => console.error("Uncaught Exception:", e));

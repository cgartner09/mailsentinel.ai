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
app.use(cors({ origin: CORS_ORIGIN === "*" ? true : [CORS_ORIGIN], credentials: true }));
app.use(morgan("combined"));

/* ----------------------- Brand + template ------------------------ */
const BRAND = { name: "MailSentinel.ai", primary: "#0ea5e9", accent: "#22c55e" };
const envelopeLogoSVG = (s=32)=>`
<svg xmlns="http://www.w3.org/2000/svg" width="${s}" height="${s}" viewBox="0 0 512 512" fill="none">
  <rect width="512" height="512" rx="100" fill="#0f172a"/>
  <defs><linearGradient id="g" x1="40" y1="120" x2="472" y2="392">
    <stop stop-color="${BRAND.primary}"/><stop offset="1" stop-color="${BRAND.accent}"/></linearGradient>
  </defs>
  <path d="M60 120h392c11 0 20 9 20 20v232c0 11-9 20-20 20H60c-11 0-20-9-20-20V140c0-11 9-20 20-20z"
    stroke="url(#g)" stroke-width="32" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
  <path d="M40 140l216 160 216-160" stroke="url(#g)" stroke-width="32" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
</svg>`;
const pageTemplate = ({ title, body }) => `<!doctype html><html lang="en"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>${title} — MailSentinel.ai</title><meta name="theme-color" content="#0f172a"/>
<script src="https://cdn.tailwindcss.com"></script>
<style>:root{--brand:${BRAND.primary};--accent:${BRAND.accent}}.btn-brand{background:var(--brand);color:#fff}.btn-brand:hover{filter:brightness(1.05)}.link-brand{color:var(--brand)}</style>
</head><body class="min-h-screen bg-slate-900 text-white">
<header class="sticky top-0 z-40 backdrop-blur bg-slate-900/80 border-b border-slate-800">
  <nav class="max-w-5xl mx-auto px-4 py-4 flex items-center justify-between">
    <a href="/" class="flex items-center gap-3">${envelopeLogoSVG(36)}<span class="font-extrabold text-2xl">MailSentinel.ai</span></a>
    <div class="hidden sm:flex items-center gap-6 text-sm">
      <a href="https://mailsentinel.ai/#features" class="text-gray-300 hover:text-white">Features</a>
      <a href="https://mailsentinel.ai/#pricing" class="text-gray-300 hover:text-white">Pricing</a>
      <a href="/logout" class="text-gray-300 hover:text-white">Log out</a>
    </div>
  </nav>
</header>
<main class="max-w-5xl mx-auto px-4 py-10">${body}</main>
<footer class="border-t border-slate-800 mt-10"><div class="max-w-5xl mx-auto px-4 py-6 text-sm text-gray-400">© ${new Date().getFullYear()} MailSentinel.ai</div></footer>
</body></html>`;

/* ---------------------- Health & readiness ----------------------- */
app.get("/health", (req, res) => {
  try {
    const r = db.prepare("SELECT 1 AS ok").get();
    res.json({ status:"ok", db: r?.ok === 1 ? "connected":"unknown", dbPath: DB_PATH, time: new Date().toISOString() });
  } catch (e) { res.status(500).json({ status:"error", error:String(e) }); }
});
app.get("/ready", (req, res) => {
  const required = ["SESSION_SECRET","DATA_KEY_HEX"];
  const missing = required.filter(k => !process.env[k]);
  if (missing.length) return res.status(500).json({ status:"not-ready", missing });
  res.json({ status:"ready", message:"All required env vars are set" });
});

/* -------------------------- Auth helpers ------------------------- */
const setAuth = (res, token) => {
  const p = process.env.NODE_ENV === "production";
  res.cookie("auth", token, { httpOnly:true, secure:p, sameSite:"lax", path:"/", maxAge:7*24*60*60*1000 });
};
const clearAuth = (res) => {
  const p = process.env.NODE_ENV === "production";
  res.cookie("auth","", { httpOnly:true, secure:p, sameSite:"lax", path:"/", maxAge:0 });
};
const signJWT = (payload) => jwt.sign(payload, process.env.SESSION_SECRET, { expiresIn:"7d" });
const readToken = (req) => {
  const c = req.headers.cookie || "";
  const m = c.match(/(?:^|;\s*)auth=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : null;
};
const requireAuth = (req, res, next) => {
  try {
    const t = readToken(req) || (req.headers.authorization||"").replace(/^Bearer\s+/i,"");
    if (!t) return res.status(401).json({ error:"unauthorized" });
    req.user = jwt.verify(t, process.env.SESSION_SECRET);
    next();
  } catch { res.status(401).json({ error:"unauthorized" }); }
};
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    if ((req.headers["accept"] || "").includes("application/json") || req.path.startsWith("/metrics")) {
      return res.status(403).json({ error:"forbidden" });
    }
    return res.status(403).type("html").send(`<!doctype html>
<html><body style="background:#0f172a;color:#e2e8f0;font-family:system-ui;padding:2rem">
  <h1 style="font-size:1.5rem;margin:0 0 .5rem">Forbidden</h1>
  <p>You need an admin account to view this page.</p>
  <a href="/tenant" style="color:#0ea5e9">Back to your dashboard</a>
</body></html>`);
  }
  next();
}

/* ------------------------- Init admin ---------------------------- */
// ... keep your /init-admin route here (unchanged) ...

/* ----------------------------- Signup ---------------------------- */
// ... keep your /signup POST + GET here (unchanged) ...

/* ------------------------------ Login ---------------------------- */
// ... keep your /login POST + GET here (unchanged) ...

/* ----------------------- Admin dashboard (global) ---------------- */
app.get("/metrics", requireAuth, requireAdmin, (req, res) => {
  // your metrics code
});
app.get("/dashboard", requireAuth, requireAdmin, (req, res) => {
  // your admin dashboard HTML render
});

/* ----------------------- Tenant (user) dashboard ----------------- */
app.get("/tenant/metrics", requireAuth, (req, res) => {
  // your tenant metrics code
});
app.get("/tenant", requireAuth, (req, res) => {
  // your tenant dashboard HTML render
});

/* ------------------------ Misc/basic routes ---------------------- */
app.post("/logout", (req, res) => { clearAuth(res); res.json({ status:"ok" }); });
app.get("/me", requireAuth, (req, res) => res.json({ user:req.user }));
app.get("/", (req, res) => res.type("text/plain").send("MailSentinel.ai backend is running"));

/* -------------------------- Errors & boot ------------------------ */
app.use((req, res) => res.status(404).json({ error:"Not found" }));
app.use((err, req, res, next) => { console.error("Unhandled", err); res.status(500).json({ error:"Internal Server Error" }); });

const PORT = Number(process.env.PORT || 3000);
const HOST = "0.0.0.0";
console.log("==== Boot ====");
console.log("PORT:", PORT);
console.log("DB_PATH:", DB_PATH);
try { console.log("DB dir exists:", fs.existsSync(path.dirname(DB_PATH))); } catch {}
app.listen(PORT, HOST, ()=>console.log(`Server listening on http://${HOST}:${PORT}`));

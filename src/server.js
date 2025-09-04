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
app.use(helmet()); // CSP defaults allow Tailwind CDN in the inline pages below
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.set("trust proxy", 1);

const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";
app.use(cors({ origin: CORS_ORIGIN === "*" ? true : [CORS_ORIGIN], credentials: true }));
app.use(morgan("combined"));

/* ----------------------- Branding + template --------------------- */
const BRAND = { name: "MailSentinel.ai", primary: "#0ea5e9", accent: "#22c55e" };

const envelopeLogoSVG = (s = 32) => `
<svg xmlns="http://www.w3.org/2000/svg" width="${s}" height="${s}" viewBox="0 0 512 512" fill="none" aria-hidden="true">
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
<style>
:root{--brand:${BRAND.primary};--accent:${BRAND.accent}}
.btn-brand{background:var(--brand);color:#fff}.btn-brand:hover{filter:brightness(1.05)}
.link-brand{color:var(--brand)}
</style>
</head><body class="min-h-screen bg-slate-900 text-white">
<header class="sticky top-0 z-40 backdrop-blur bg-slate-900/80 border-b border-slate-800">
  <nav class="max-w-5xl mx-auto px-4 py-4 flex items-center justify-between">
    <a href="/" class="flex items-center gap-3">
      ${envelopeLogoSVG(36)}<span class="font-extrabold text-2xl">MailSentinel.ai</span>
    </a>
    <div class="hidden sm:flex items-center gap-6 text-sm">
      <a href="https://mailsentinel.ai/#features" class="text-gray-300 hover:text-white">Features</a>
      <a href="https://mailsentinel.ai/#pricing" class="text-gray-300 hover:text-white">Pricing</a>
      <a href="/logout" class="text-gray-300 hover:text-white">Log out</a>
    </div>
  </nav>
</header>
<main class="max-w-5xl mx-auto px-4 py-10">${body}</main>
<footer class="border-t border-slate-800 mt-10">
  <div class="max-w-5xl mx-auto px-4 py-6 text-sm text-gray-400">© ${new Date().getFullYear()} MailSentinel.ai</div>
</footer>
</body></html>`;

/* ---------------------- Health & readiness ----------------------- */
app.get("/health", (req, res) => {
  try {
    const r = db.prepare("SELECT 1 AS ok").get();
    res.json({ status: "ok", db: r?.ok === 1 ? "connected" : "unknown", dbPath: DB_PATH, time: new Date().toISOString() });
  } catch (e) { res.status(500).json({ status: "error", error: String(e) }); }
});

app.get("/ready", (req, res) => {
  const required = ["SESSION_SECRET", "DATA_KEY_HEX"];
  const missing = required.filter(k => !process.env[k]);
  if (missing.length) return res.status(500).json({ status: "not-ready", missing });
  res.json({ status: "ready", message: "All required env vars are set" });
});

/* -------------------------- Auth helpers ------------------------- */
// set/clear JWT cookie without cookie-parser
const setAuth = (res, token) => {
  const p = process.env.NODE_ENV === "production";
  res.cookie("auth", token, { httpOnly: true, secure: p, sameSite: "lax", path: "/", maxAge: 7*24*60*60*1000 });
};
const clearAuth = (res) => {
  const p = process.env.NODE_ENV === "production";
  res.cookie("auth", "", { httpOnly: true, secure: p, sameSite: "lax", path: "/", maxAge: 0 });
};
const signJWT = (payload) => jwt.sign(payload, process.env.SESSION_SECRET, { expiresIn: "7d" });
const readToken = (req) => {
  const c = req.headers.cookie || "";
  const m = c.match(/(?:^|;\s*)auth=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : null;
};
const requireAuth = (req, res, next) => {
  try {
    const t = readToken(req) || (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
    if (!t) return res.status(401).json({ error: "unauthorized" });
    req.user = jwt.verify(t, process.env.SESSION_SECRET);
    next();
  } catch { return res.status(401).json({ error: "unauthorized" }); }
};
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    // JSON for APIs, minimal HTML for pages
    if ((req.headers["accept"] || "").includes("application/json") || req.path.startsWith("/metrics")) {
      return res.status(403).json({ error: "forbidden" });
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

/* --------------------------- Init admin -------------------------- */
/**
 * POST /init-admin
 * Header: x-init-token: <INIT_TOKEN>
 * Reads ADMIN_EMAIL, ADMIN_PASSWORD from env.
 */
app.post("/init-admin", async (req, res) => {
  try {
    const provided = req.header("x-init-token") || req.query.token || req.body?.token || "";
    const INIT = (process.env.INIT_TOKEN || "").trim();
    if (!INIT) return res.status(500).json({ error: "INIT_TOKEN is not set" });
    if (provided !== INIT) return res.status(401).json({ error: "Unauthorized" });

    const ADMIN = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
    const PASS = (process.env.ADMIN_PASSWORD || "").trim();
    if (!ADMIN || !PASS) return res.status(400).json({ error: "ADMIN_EMAIL and ADMIN_PASSWORD must be set" });

    const domain = ADMIN.split("@").pop();
    const existing = db.prepare("SELECT id, tenant_id FROM users WHERE email=?").get(ADMIN);
    if (existing) return res.json({ status: "exists", userId: existing.id, tenantId: existing.tenant_id });

    let tenant = db.prepare("SELECT id FROM tenants WHERE domain=?").get(domain);
    if (!tenant) {
      db.prepare("INSERT INTO tenants(domain) VALUES(?)").run(domain);
      tenant = db.prepare("SELECT id FROM tenants WHERE domain=?").get(domain);
    }

    const hash = await argon2.hash(PASS);
    const result = db.prepare("INSERT INTO users(tenant_id,email,password_hash,role) VALUES(?,?,?,'admin')")
      .run(tenant.id, ADMIN, hash);

    // Ensure default API key for tenant
    const keyExists = db.prepare("SELECT id FROM api_keys WHERE tenant_id=?").get(tenant.id);
    if (!keyExists) {
      const key = `msk_${crypto.randomBytes(24).toString("hex")}`;
      db.prepare("INSERT INTO api_keys(tenant_id,name,key) VALUES(?,?,?)").run(tenant.id, "Default", key);
    }

    res.status(201).json({ status: "created", tenantId: tenant.id, userId: result.lastInsertRowid });
  } catch (e) { console.error("init-admin", e); res.status(500).json({ error: "failed to init", detail: String(e) }); }
});

/* ----------------------------- Signup ---------------------------- */
app.post("/signup", async (req, res) => {
  try {
    const { email, password, company, plan } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: "email and password are required" });
    const emailNorm = String(email).trim().toLowerCase();
    if (!emailNorm.includes("@")) return res.status(400).json({ error: "invalid email" });
    const domain = emailNorm.split("@").pop();

    const exists = db.prepare("SELECT id FROM users WHERE email=?").get(emailNorm);
    if (exists) return res.status(409).json({ error: "account already exists" });

    let tenant = db.prepare("SELECT id FROM tenants WHERE domain=?").get(domain);
    if (!tenant) {
      db.prepare("INSERT INTO tenants(domain) VALUES(?)").run(domain);
      tenant = db.prepare("SELECT id FROM tenants WHERE domain=?").get(domain);
    }

    const count = db.prepare("SELECT COUNT(*) AS c FROM users WHERE tenant_id=?").get(tenant.id).c;
    const role = count === 0 ? "admin" : "member";

    const hash = await argon2.hash(String(password));
    const result = db.prepare("INSERT INTO users(tenant_id,email,password_hash,role) VALUES(?,?,?,?)")
      .run(tenant.id, emailNorm, hash, role);

    // Ensure API key exists for this tenant
    const keyExists = db.prepare("SELECT id FROM api_keys WHERE tenant_id=?").get(tenant.id);
    if (!keyExists) {
      const key = `msk_${crypto.randomBytes(24).toString("hex")}`;
      db.prepare("INSERT INTO api_keys(tenant_id,name,key) VALUES(?,?,?)").run(tenant.id, "Default", key);
    }

    const token = signJWT({ sub: String(result.lastInsertRowid), email: emailNorm, tenantId: tenant.id, role });
    setAuth(res, token);
    res.status(201).json({ status: "created", tenantId: tenant.id, userId: result.lastInsertRowid, role, plan: plan || null, company: company || null, redirect: "/tenant" });
  } catch (e) { console.error("signup", e); res.status(500).json({ error: "Failed to sign up", detail: String(e) }); }
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
        <div><label class="text-sm font-medium">Email</label>
          <input name="email" type="email" required class="mt-1 w-full rounded-xl border border-slate-600 bg-slate-900 px-3 py-2 text-white" placeholder="you@company.com"/></div>
        <div><label class="text-sm font-medium">Password</label>
          <input name="password" type="password" required class="mt-1 w-full rounded-xl border border-slate-600 bg-slate-900 px-3 py-2 text-white" placeholder="••••••••"/></div>
        <div><label class="text-sm font-medium">Company</label>
          <input name="company" class="mt-1 w-full rounded-xl border border-slate-600 bg-slate-900 px-3 py-2 text-white" placeholder="Company LLC"/></div>
        <div><label class="text-sm font-medium">Plan</label>
          <select name="plan" class="mt-1 w-full rounded-xl border border-slate-600 bg-slate-900 px-3 py-2 text-white">
            <option value="">(none)</option>
            <option value="starter">Starter ($10 / 3 inboxes)</option>
            <option value="pro">Pro ($25 / 50 mailboxes)</option>
            <option value="business">Business ($299)</option>
          </select></div>
        <button type="submit" class="w-full btn-brand rounded-2xl px-4 py-3 font-semibold">Sign Up</button>
        <p class="text-center text-sm text-gray-400">Already have an account? <a href="/login" class="link-brand hover:underline">Log in</a></p>
      </form>
    </div>
  </section>`;
  res.type("html").send(pageTemplate({ title: "Sign Up", body }));
});

/* ------------------------------ Login ---------------------------- */
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: "email and password are required" });

    const emailNorm = String(email).trim().toLowerCase();
    const user = db.prepare("SELECT id, tenant_id, email, password_hash, role FROM users WHERE email=?").get(emailNorm);
    if (!user) return res.status(401).json({ error: "invalid credentials" });

    const ok = await argon2.verify(user.password_hash, String(password));
    if (!ok) return res.status(401).json({ error: "invalid credentials" });

    const token = signJWT({ sub: String(user.id), email: user.email, tenantId: user.tenant_id, role: user.role });
    setAuth(res, token);
    res.json({ status: "ok", tenantId: user.tenant_id, userId: user.id, role: user.role, redirect: "/tenant" });
  } catch (e) { console.error("login", e); res.status(500).json({ error: "Failed to login", detail: String(e) }); }
});

app.get("/login", (req, res) => {
  const body = `
  <section class="relative">
    <div class="absolute -top-24 -right-24 w-[28rem] h-[28rem] rounded-full blur-3xl opacity-20" style="background:${BRAND.primary}"></div>
    <div class="absolute -bottom-24 -left-24 w-[28rem] h-[28rem] rounded-full blur-3xl opacity-20" style="background:${BRAND.accent}"></div>
    <div class="max-w-xl mx-auto mt-6">
      <h1 class="text-3xl md:text-4xl font-extrabold">Welcome back</h1>
      <p class="mt-2 text-gray-300">Log in to view threats and manage settings.</p>
      <form method="POST" action="/login" class="mt-6 bg-slate-800 border border-slate-700 rounded-2xl p-6 space-y-4 shadow">
        <div><label class="text-sm font-medium">Email</label>
          <input name="email" type="email" required class="mt-1 w-full rounded-xl border border-slate-600 bg-slate-900 px-3 py-2 text-white" placeholder="you@company.com"/></div>
        <div><label class="text-sm font-medium">Password</label>
          <input name="password" type="password" required class="mt-1 w-full rounded-xl border border-slate-600 bg-slate-900 px-3 py-2 text-white" placeholder="••••••••"/></div>
        <button type="submit" class="w-full btn-brand rounded-2xl px-4 py-3 font-semibold">Log In</button>
        <p class="text-center text-sm text-gray-400">New here? <a href="/signup" class="link-brand hover:underline">Create an account</a></p>
      </form>
    </div>
  </section>`;
  res.type("html").send(pageTemplate({ title: "Login", body }));
});

/* ----------------------- Admin dashboard (global) ---------------- */
app.get("/metrics", requireAuth, requireAdmin, (req, res) => {
  const q = (sql, p = []) => db.prepare(sql).all(...p);
  const s = (sql, p = []) => db.prepare(sql).get(...p);

  const totalUsers = s("SELECT COUNT(*) AS c FROM users").c;
  const totalTenants = s("SELECT COUNT(*) AS c FROM tenants").c;
  const signupsToday = s("SELECT COUNT(*) AS c FROM users WHERE date(created_at)=date('now')").c;
  const signups7d = s("SELECT COUNT(*) AS c FROM users WHERE datetime(created_at) >= datetime('now','-7 day')").c;

  const revenueToday = s("SELECT COALESCE(SUM(amount_cents),0) AS s FROM purchases WHERE status='paid' AND date(created_at)=date('now')").s;
  const revenueMTD   = s("SELECT COALESCE(SUM(amount_cents),0) AS s FROM purchases WHERE status='paid' AND strftime('%Y-%m',created_at)=strftime('%Y-%m','now')").s;

  const planRows = q("SELECT plan, COUNT(*) AS c FROM purchases WHERE status='paid' GROUP BY plan");
  const plans = { starter: 0, pro: 0, business: 0 };
  for (const r of planRows) plans[r.plan] = r.c;

  const lastPurchases = q("SELECT plan, amount_cents, status, currency, created_at FROM purchases ORDER BY created_at DESC LIMIT 10");
  const lastSignups   = q("SELECT email, created_at FROM users ORDER BY created_at DESC LIMIT 10");

  res.json({ totals: { totalUsers, totalTenants, signupsToday, signups7d }, revenue: { revenueToday, revenueMTD, currency: "usd" }, plans, lastPurchases, lastSignups });
});

app.get("/dashboard", requireAuth, requireAdmin, (req, res) => {
  const body = `
  <section class="relative">
    <div class="absolute -top-24 -right-24 w-[28rem] h-[28rem] rounded-full blur-3xl opacity-20" style="background:${BRAND.primary}"></div>
    <div class="absolute -bottom-24 -left-24 w-[28rem] h-[28rem] rounded-full blur-3xl opacity-20" style="background:${BRAND.accent}"></div>

    <div class="flex items-center justify-between">
      <div><h1 class="text-3xl md:text-4xl font-extrabold">Admin Dashboard</h1>
      <p class="text-gray-300">Signed in as <span class="font-semibold">${req.user.email}</span></p></div>
      <form method="POST" action="/logout"><button class="btn-brand rounded-xl px-4 py-2">Log out</button></form>
    </div>

    <div id="cards" class="mt-6 grid md:grid-cols-4 gap-4"></div>

    <div class="mt-8 grid lg:grid-cols-2 gap-6">
      <div class="rounded-2xl border border-slate-700 bg-slate-800 p-6">
        <h3 class="text-lg font-semibold mb-4">Latest Purchases</h3>
        <table class="w-full text-sm"><thead class="text-left text-gray-400"><tr><th>When</th><th>Plan</th><th>Amount</th><th>Status</th></tr></thead><tbody id="purchases" class="text-gray-200"></tbody></table>
      </div>
      <div class="rounded-2xl border border-slate-700 bg-slate-800 p-6">
        <h3 class="text-lg font-semibold mb-4">Latest Signups</h3>
        <table class="w-full text-sm"><thead class="text-left text-gray-400"><tr><th>When</th><th>Email</th></tr></thead><tbody id="signups" class="text-gray-2 00"></tbody></table>
      </div>
    </div>

    <script>
      const fmtUSD = (c)=>'$'+(c/100).toLocaleString();
      async function load(){
        const r = await fetch('/metrics', { credentials: 'include' });
        if(!r.ok) return;
        const m = await r.json();
        const cards = [
          { label:'Users', value:m.totals.totalUsers },
          { label:'Tenants', value:m.totals.totalTenants },
          { label:'Signups (Today)', value:m.totals.signupsToday },
          { label:'Signups (7d)', value:m.totals.signups7d },
          { label:'Revenue (Today)', value:fmtUSD(m.revenue.revenueToday) },
          { label:'Revenue (MTD)', value:fmtUSD(m.revenue.revenueMTD) },
          { label:'Paid Plans — Pro', value:m.plans.pro },
          { label:'Paid Plans — Business', value:m.plans.business }
        ];
        document.getElementById('cards').innerHTML = cards.map(c => \`
          <div class="rounded-2xl border border-slate-700 bg-slate-800 p-6">
            <div class="text-sm text-gray-400">\${c.label}</div>
            <div class="text-2xl font-bold mt-1">\${c.value}</div>
          </div>\`).join('');
        document.getElementById('purchases').innerHTML = (m.lastPurchases||[]).map(p=>\`
          <tr class="border-t border-slate-700/60"><td>\${new Date(p.created_at).toLocaleString()}</td><td class="capitalize">\${p.plan}</td><td>\${fmtUSD(p.amount_cents)}</td><td class="uppercase text-xs">\${p.status}</td></tr>\`).join('');
        document.getElementById('signups').innerHTML = (m.lastSignups||[]).map(s=>\`
          <tr class="border-t border-slate-700/60"><td>\${new Date(s.created_at).toLocaleString()}</td><td>\${s.email}</td></tr>\`).join('');
      }
      load(); setInterval(load, 5000);
    </script>
  </section>`;
  res.type("html").send(pageTemplate({ title: "Admin Dashboard", body }));
});

/* ----------------------- Tenant (customer) views ----------------- */
// Tenant metrics JSON for the logged-in user's company
app.get("/tenant/metrics", requireAuth, (req, res) => {
  const tenantId = req.user.tenantId;
  const s = (sql, ...p) => db.prepare(sql).get(...p);
  const a = (sql, ...p) => db.prepare(sql).all(...p);

  const seats      = s("SELECT COUNT(*) AS c FROM users WHERE tenant_id=?", tenantId).c;
  const threatsAll = s("SELECT COUNT(*) AS c FROM quarantines WHERE tenant_id=?", tenantId).c;
  const threats24h = s("SELECT COUNT(*) AS c FROM quarantines WHERE tenant_id=? AND datetime(created_at)>=datetime('now','-24 hour')", tenantId).c;
  const threats7d  = s("SELECT COUNT(*) AS c FROM quarantines WHERE tenant_id=? AND datetime(created_at)>=datetime('now','-7 day')", tenantId).c;

  const lastQuarantine = a("SELECT message_id, reason, created_at FROM quarantines WHERE tenant_id=? ORDER BY created_at DESC LIMIT 20", tenantId);

  // Ensure tenant has an API key; create one if not
  let keyRow = s("SELECT key FROM api_keys WHERE tenant_id=? ORDER BY created_at ASC LIMIT 1", tenantId);
  if (!keyRow) {
    const newKey = `msk_${crypto.randomBytes(24).toString("hex")}`;
    db.prepare("INSERT INTO api_keys(tenant_id,name,key) VALUES(?,?,?)").run(tenantId, "Default", newKey);
    keyRow = { key: newKey };
  }

  res.json({
    tenantId,
    seats,
    threats: { all: threatsAll, h24: threats24h, d7: threats7d },
    apiKeyPreview: keyRow.key.slice(0, 8) + "…",
    quarantine: lastQuarantine
  });
});

// Tenant dashboard HTML
app.get("/tenant", requireAuth, (req, res) => {
  const body = `
  <section class="relative">
    <div class="absolute -top-24 -right-24 w-[28rem] h-[28rem] rounded-full blur-3xl opacity-20" style="background:${BRAND.primary}"></div>
    <div class="absolute -bottom-24 -left-24 w-[28rem] h-[28rem] rounded-full blur-3xl opacity-20" style="background:${BRAND.accent}"></div>

    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-3xl md:text-4xl font-extrabold">Your Security Dashboard</h1>
        <p class="text-gray-300">Signed in as <span class="font-semibold">${req.user.email}</span></p>
      </div>
      <div class="flex gap-2">
        ${req.user.role === "admin" ? `<form method="POST" action="/simulate/threat"><button class="btn-brand rounded-xl px-3 py-2 text-sm">Simulate threat</button></form>` : ""}
        <form method="POST" action="/logout"><button class="rounded-xl px-3 py-2 text-sm border border-slate-600">Log out</button></form>
      </div>
    </div>

    <div id="cards" class="mt-6 grid md:grid-cols-4 gap-4"></div>

    <div class="mt-8 grid lg:grid-cols-2 gap-6">
      <div class="rounded-2xl border border-slate-700 bg-slate-800 p-6">
        <h3 class="text-lg font-semibold mb-4">Integration</h3>
        <p class="text-sm text-gray-300">Use your API key with our inbound gateway or SIEM export.</p>
        <div id="apikey" class="mt-3 text-gray-200"></div>
        <pre class="mt-4 bg-slate-900 border border-slate-700 rounded-xl p-3 text-xs overflow-x-auto">
curl -H "Authorization: Bearer &lt;YOUR_API_KEY&gt;" https://api.mailsentinel.ai/v1/quarantine</pre>
      </div>

      <div class="rounded-2xl border border-slate-700 bg-slate-800 p-6">
        <h3 class="text-lg font-semibold mb-4">Latest Quarantined Emails</h3>
        <table class="w-full text-sm">
          <thead class="text-left text-gray-400"><tr><th>When</th><th>Message ID</th><th>Reason</th></tr></thead>
          <tbody id="quarantine" class="text-gray-200"></tbody>
        </table>
      </div>
    </div>

    <script>
      async function load(){
        const r = await fetch('/tenant/metrics', { credentials:'include' });
        if(!r.ok) return;
        const m = await r.json();

        const cards = [
          { label:'Seats', value:m.seats },
          { label:'Threats (24h)', value:m.threats.h24 },
          { label:'Threats (7d)', value:m.threats.d7 },
          { label:'Threats (All-time)', value:m.threats.all }
        ];
        document.getElementById('cards').innerHTML = cards.map(c=>\`
          <div class="rounded-2xl border border-slate-700 bg-slate-800 p-6">
            <div class="text-sm text-gray-400">\${c.label}</div>
            <div class="text-2xl font-bold mt-1">\${c.value}</div>
          </div>\`).join('');

        document.getElementById('apikey').textContent = 'API Key: ' + m.apiKeyPreview + ' (full key is hidden for security)';

        document.getElementById('quarantine').innerHTML = (m.quarantine||[]).map(q=>\`
          <tr class="border-t border-slate-700/60"><td>\${new Date(q.created_at).toLocaleString()}</td><td>\${q.message_id}</td><td class="capitalize">\${q.reason}</td></tr>
        \`).join('');
      }
      load(); setInterval(load, 5000);
    </script>
  </section>`;
  res.type("html").send(pageTemplate({ title: "Tenant Dashboard", body }));
});

/* ----------- Admin-only helper: simulate quarantined threat ------ */
app.post("/simulate/threat", requireAuth, requireAdmin, (req, res) => {
  const tenantId = req.user.tenantId;
  const msgId = `msg_${crypto.randomBytes(6).toString("hex")}`;
  const reasons = ["phishing", "malware", "spoofing", "link-bait", "suspicious attachment"];
  const reason = reasons[Math.floor(Math.random()*reasons.length)];
  db.prepare("INSERT INTO quarantines(tenant_id,message_id,reason,meta) VALUES(?,?,?,?)")
    .run(tenantId, msgId, reason, JSON.stringify({ simulated: true }));
  if ((req.headers["content-type"] || "").includes("application/json")) {
    res.json({ status: "ok", inserted: msgId });
  } else {
    res.redirect("/tenant");
  }
});

/* ------------------------ Misc/basic routes ---------------------- */
app.post("/logout", (req, res) => { clearAuth(res); res.json({ status: "ok" }); });
app.get("/me", requireAuth, (req, res) => res.json({ user: req.user }));
app.get("/", (req, res) => res.type("text/plain").send("MailSentinel.ai backend is running"));

/* -------------------------- Errors & boot ------------------------ */
app.use((req, res) => res.status(404).json({ error: "Not found" }));
app.use((err, req, res, next) => { console.error("Unhandled", err); res.status(500).json({ error: "Internal Server Error" }); });

const PORT = Number(process.env.PORT || 3000);
const HOST = "0.0.0.0";
console.log("==== Boot ====");
console.log("PORT:", PORT);
console.log("CORS_ORIGIN:", CORS_ORIGIN);
console.log("APP_PUBLIC_URL:", process.env.APP_PUBLIC_URL || "(unset)");
console.log("DB_PATH:", DB_PATH);
try { console.log("DB dir exists:", fs.existsSync(path.dirname(DB_PATH))); } catch {}
app.listen(PORT, HOST, () => console.log(`Server listening on http://${HOST}:${PORT}`));

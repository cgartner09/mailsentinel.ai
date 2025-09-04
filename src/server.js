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
/* ---------- core ---------- */
app.use(helmet());
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.set("trust proxy", 1);
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";
app.use(cors({ origin: CORS_ORIGIN === "*" ? true : [CORS_ORIGIN], credentials: true }));
app.use(morgan("combined"));

/* ---------- helpers ---------- */
const BRAND = { name: "MailSentinel.ai", primary: "#0ea5e9", accent: "#22c55e" };
const envelopeLogoSVG = (s=32)=>`<svg xmlns="http://www.w3.org/2000/svg" width="${s}" height="${s}" viewBox="0 0 512 512" fill="none"><rect width="512" height="512" rx="100" fill="#0f172a"/><defs><linearGradient id="g" x1="40" y1="120" x2="472" y2="392"><stop stop-color="${BRAND.primary}"/><stop offset="1" stop-color="${BRAND.accent}"/></linearGradient></defs><path d="M60 120h392c11 0 20 9 20 20v232c0 11-9 20-20 20H60c-11 0-20-9-20-20V140c0-11 9-20 20-20z" stroke="url(#g)" stroke-width="32" stroke-linecap="round" stroke-linejoin="round" fill="none"/><path d="M40 140l216 160 216-160" stroke="url(#g)" stroke-width="32" stroke-linecap="round" stroke-linejoin="round" fill="none"/></svg>`;
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

/* ---------- health/ready ---------- */
app.get("/health",(req,res)=>{try{const r=db.prepare("SELECT 1 AS ok").get();res.json({status:"ok",db:r?.ok===1?"connected":"unknown",dbPath:DB_PATH,time:new Date().toISOString()});}catch(e){res.status(500).json({status:"error",error:String(e)})}});
app.get("/ready",(req,res)=>{const reqd=["SESSION_SECRET","DATA_KEY_HEX"];const missing=reqd.filter(k=>!process.env[k]);if(missing.length)return res.status(500).json({status:"not-ready",missing});res.json({status:"ready",message:"All required env vars are set"})});

/* ---------- auth cookie helpers ---------- */
const setAuth=(res,token)=>{const p=process.env.NODE_ENV==="production";res.cookie("auth",token,{httpOnly:true,secure:p,sameSite:"lax",path:"/",maxAge:7*24*60*60*1000});};
const clearAuth=(res)=>{const p=process.env.NODE_ENV==="production";res.cookie("auth","",{httpOnly:true,secure:p,sameSite:"lax",path:"/",maxAge:0});};
const signJWT=(payload)=>jwt.sign(payload,process.env.SESSION_SECRET,{expiresIn:"7d"});
const readToken=(req)=>{const c=req.headers.cookie||"";const m=c.match(/(?:^|;\\s*)auth=([^;]+)/);return m?decodeURIComponent(m[1]):null;}
const requireAuth=(req,res,next)=>{try{const t=readToken(req)||(req.headers.authorization||"").replace(/^Bearer\\s+/i,"");if(!t)return res.status(401).json({error:"unauthorized"});req.user=jwt.verify(t,process.env.SESSION_SECRET);next();}catch{res.status(401).json({error:"unauthorized"});}};

/* ---------- init-admin ---------- */
app.post("/init-admin", async (req,res)=>{
  try{
    const provided=req.header("x-init-token")||req.query.token||req.body?.token||"";
    const INIT=(process.env.INIT_TOKEN||"").trim();
    if(!INIT) return res.status(500).json({error:"INIT_TOKEN is not set"});
    if(provided!==INIT) return res.status(401).json({error:"Unauthorized"});
    const ADMIN=(process.env.ADMIN_EMAIL||"").trim().toLowerCase();
    const PASS=(process.env.ADMIN_PASSWORD||"").trim();
    if(!ADMIN||!PASS) return res.status(400).json({error:"ADMIN_EMAIL and ADMIN_PASSWORD must be set"});
    const domain=ADMIN.split("@").pop();
    const ex=db.prepare("SELECT id,tenant_id FROM users WHERE email=?").get(ADMIN);
    if(ex) return res.json({status:"exists",userId:ex.id,tenantId:ex.tenant_id});
    let tenant=db.prepare("SELECT id FROM tenants WHERE domain=?").get(domain);
    if(!tenant){db.prepare("INSERT INTO tenants(domain) VALUES(?)").run(domain);tenant=db.prepare("SELECT id FROM tenants WHERE domain=?").get(domain);}
    const hash=await argon2.hash(PASS);
    const result=db.prepare("INSERT INTO users(tenant_id,email,password_hash,role) VALUES(?,?,?,'admin')").run(tenant.id,ADMIN,hash);
    res.status(201).json({status:"created",tenantId:tenant.id,userId:result.lastInsertRowid});
  }catch(e){console.error(e);res.status(500).json({error:"failed to init",detail:String(e)})}
});

/* ---------- signup/login ---------- */
app.post("/signup", async (req,res)=>{
  try{
    const {email,password,company,plan}=req.body||{};
    if(!email||!password) return res.status(400).json({error:"email and password are required"});
    const emailNorm=String(email).trim().toLowerCase();
    const domain=emailNorm.split("@").pop();
    const exists=db.prepare("SELECT id FROM users WHERE email=?").get(emailNorm);
    if(exists) return res.status(409).json({error:"account already exists"});
    let tenant=db.prepare("SELECT id FROM tenants WHERE domain=?").get(domain);
    if(!tenant){db.prepare("INSERT INTO tenants(domain) VALUES(?)").run(domain);tenant=db.prepare("SELECT id FROM tenants WHERE domain=?").get(domain);}
    const count=db.prepare("SELECT COUNT(*) AS c FROM users WHERE tenant_id=?").get(tenant.id).c;
    const role=count===0?"admin":"member";
    const hash=await argon2.hash(String(password));
    const result=db.prepare("INSERT INTO users(tenant_id,email,password_hash,role) VALUES(?,?,?,?)").run(tenant.id,emailNorm,hash,role);
    const token=signJWT({sub:String(result.lastInsertRowid),email:emailNorm,tenantId:tenant.id,role});
    setAuth(res,token);
    res.status(201).json({status:"created",tenantId:tenant.id,userId:result.lastInsertRowid,role,plan:plan||null,company:company||null,redirect:"/dashboard"});
  }catch(e){console.error("signup",e);res.status(500).json({error:"Failed to sign up",detail:String(e)})}
});
app.get("/signup",(req,res)=>{const body=`
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
      <div><label class="text-sm font-medium">Plan</label><select name="plan" class="mt-1 w-full rounded-xl border border-slate-600 bg-slate-900 px-3 py-2 text-white">
        <option value="">(none)</option><option value="starter">Starter ($10 / 3 inboxes)</option><option value="pro">Pro ($25 / 50 mailboxes)</option><option value="business">Business ($299)</option>
      </select></div>
      <button type="submit" class="w-full btn-brand rounded-2xl px-4 py-3 font-semibold">Sign Up</button>
      <p class="text-center text-sm text-gray-400">Already have an account? <a href="/login" class="link-brand hover:underline">Log in</a></p>
    </form>
  </div>
</section>`;res.type("html").send(pageTemplate({title:"Sign Up",body}))});

app.post("/login", async (req,res)=>{
  try{
    const {email,password}=req.body||{};
    if(!email||!password) return res.status(400).json({error:"email and password are required"});
    const emailNorm=String(email).trim().toLowerCase();
    const user=db.prepare("SELECT id,tenant_id,email,password_hash,role FROM users WHERE email=?").get(emailNorm);
    if(!user) return res.status(401).json({error:"invalid credentials"});
    const ok=await argon2.verify(user.password_hash,String(password));
    if(!ok) return res.status(401).json({error:"invalid credentials"});
    const token=signJWT({sub:String(user.id),email:user.email,tenantId:user.tenant_id,role:user.role});
    setAuth(res,token);
    res.json({status:"ok",tenantId:user.tenant_id,userId:user.id,role:user.role,redirect:"/dashboard"});
  }catch(e){console.error("login",e);res.status(500).json({error:"Failed to login",detail:String(e)})}
});
app.get("/login",(req,res)=>{const body=`
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
</section>`;res.type("html").send(pageTemplate({title:"Login",body}))});

/* ---------- metrics + dashboard ---------- */
const PLAN_PRICE = { starter: 1000, pro: 2500, business: 29900 }; // cents

app.get("/metrics", requireAuth, (req, res) => {
  const q = (sql, p=[]) => db.prepare(sql).all(...p);
  const s = (sql, p=[]) => db.prepare(sql).get(...p);

  const totalUsers = s("SELECT COUNT(*) AS c FROM users").c;
  const totalTenants = s("SELECT COUNT(*) AS c FROM tenants").c;
  const signupsToday = s("SELECT COUNT(*) AS c FROM users WHERE date(created_at)=date('now')").c;
  const signups7d = s("SELECT COUNT(*) AS c FROM users WHERE datetime(created_at) >= datetime('now','-7 day')").c;

  const revenueToday = s("SELECT COALESCE(SUM(amount_cents),0) AS s FROM purchases WHERE status='paid' AND date(created_at)=date('now')").s;
  const revenueMTD = s("SELECT COALESCE(SUM(amount_cents),0) AS s FROM purchases WHERE status='paid' AND strftime('%Y-%m',created_at)=strftime('%Y-%m','now')").s;

  const planRows = q("SELECT plan, COUNT(*) AS c FROM purchases WHERE status='paid' GROUP BY plan");
  const planBreakdown = { starter: 0, pro: 0, business: 0 };
  for (const r of planRows) planBreakdown[r.plan] = r.c;

  const lastPurchases = q("SELECT plan, amount_cents, status, currency, created_at FROM purchases ORDER BY created_at DESC LIMIT 10");
  const lastSignups = q("SELECT email, created_at FROM users ORDER BY created_at DESC LIMIT 10");

  res.json({
    totals: { totalUsers, totalTenants, signupsToday, signups7d },
    revenue: { revenueToday, revenueMTD, currency: "usd" },
    plans: planBreakdown,
    lastPurchases,
    lastSignups
  });
});

app.get("/dashboard", requireAuth, (req, res) => {
  const body = `
  <section class="relative">
    <div class="absolute -top-24 -right-24 w-[28rem] h-[28rem] rounded-full blur-3xl opacity-20" style="background:${BRAND.primary}"></div>
    <div class="absolute -bottom-24 -left-24 w-[28rem] h-[28rem] rounded-full blur-3xl opacity-20" style="background:${BRAND.accent}"></div>

    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-3xl md:text-4xl font-extrabold">Dashboard</h1>
        <p class="text-gray-300">Welcome, <span class="font-semibold">${req.user.email}</span></p>
      </div>
      <form method="POST" action="/logout"><button class="btn-brand rounded-xl px-4 py-2">Log out</button></form>
    </div>

    <div id="cards" class="mt-6 grid md:grid-cols-4 gap-4"></div>

    <div class="mt-8 grid lg:grid-cols-2 gap-6">
      <div class="rounded-2xl border border-slate-700 bg-slate-800 p-6">
        <h3 class="text-lg font-semibold mb-4">Latest Purchases</h3>
        <table class="w-full text-sm">
          <thead class="text-left text-gray-400"><tr><th>When</th><th>Plan</th><th>Amount</th><th>Status</th></tr></thead>
          <tbody id="purchases" class="text-gray-200"></tbody>
        </table>
      </div>
      <div class="rounded-2xl border border-slate-700 bg-slate-800 p-6">
        <h3 class="text-lg font-semibold mb-4">Latest Signups</h3>
        <table class="w-full text-sm">
          <thead class="text-left text-gray-400"><tr><th>When</th><th>Email</th></tr></thead>
          <tbody id="signups" class="text-gray-200"></tbody>
        </table>
      </div>
    </div>

    <script>
      const fmtUSD = (cents)=>'$'+(cents/100).toLocaleString();
      async function load(){
        const r = await fetch('/metrics', { credentials: 'include' });
        if(!r.ok) return;
        const m = await r.json();

        const cards = [
          { label: 'Users', value: m.totals.totalUsers },
          { label: 'Tenants', value: m.totals.totalTenants },
          { label: 'Signups (Today)', value: m.totals.signupsToday },
          { label: 'Signups (7d)', value: m.totals.signups7d },
          { label: 'Revenue (Today)', value: fmtUSD(m.revenue.revenueToday) },
          { label: 'Revenue (MTD)', value: fmtUSD(m.revenue.revenueMTD) },
          { label: 'Paid Plans — Pro', value: m.plans.pro },
          { label: 'Paid Plans — Business', value: m.plans.business }
        ];

        document.getElementById('cards').innerHTML = cards.map(c => \`
          <div class="rounded-2xl border border-slate-700 bg-slate-800 p-6">
            <div class="text-sm text-gray-400">\${c.label}</div>
            <div class="text-2xl font-bold mt-1">\${c.value}</div>
          </div>\`).join('');

        document.getElementById('purchases').innerHTML = (m.lastPurchases||[]).map(p=>\`
          <tr class="border-t border-slate-700/60"><td>\${new Date(p.created_at).toLocaleString()}</td><td class="capitalize">\${p.plan}</td><td>\${fmtUSD(p.amount_cents)}</td><td class="uppercase text-xs">\${p.status}</td></tr>
        \`).join('');

        document.getElementById('signups').innerHTML = (m.lastSignups||[]).map(s=>\`
          <tr class="border-t border-slate-700/60"><td>\${new Date(s.created_at).toLocaleString()}</td><td>\${s.email}</td></tr>
        \`).join('');
      }
      load(); setInterval(load, 5000);
    </script>
  </section>`;
  res.type("html").send(pageTemplate({ title: "Dashboard", body }));
});

/* ---------- logout, me, root ---------- */
app.post("/logout",(req,res)=>{clearAuth(res);res.json({status:"ok"})});
app.get("/me", requireAuth, (req,res)=>res.json({user:req.user}));
app.get("/",(req,res)=>res.type("text/plain").send("MailSentinel.ai backend is running"));

/* ---------- Stripe webhook (optional; populate purchases) ---------- */
app.post("/webhooks/stripe", express.raw({ type: "*/*" }), (req, res) => {
  try {
    const secret = process.env.STRIPE_WEBHOOK_SECRET || "";
    let event;
    if (secret) {
      const sig = req.header("stripe-signature");
      // Normally verify here using Stripe SDK. For now we store event for inspection.
    }
    // naive parse:
    const payload = req.body?.toString() || "";
    db.prepare("INSERT INTO events(type, payload) VALUES(?, ?)").run("stripe", payload);

    // TODO: parse payload JSON and INSERT INTO purchases(...) with real amounts/status.
    res.status(200).send("ok");
  } catch (e) {
    console.error("stripe webhook error", e);
    res.status(400).send("bad request");
  }
});

/* ---------- errors + startup ---------- */
app.use((req,res)=>res.status(404).json({error:"Not found"}));
app.use((err,req,res,next)=>{console.error("Unhandled",err);res.status(500).json({error:"Internal Server Error"})});

const PORT = Number(process.env.PORT || 3000);
const HOST = "0.0.0.0";
console.log("==== Boot ====");
console.log("PORT:", PORT);
console.log("DB_PATH:", DB_PATH);
try { console.log("DB dir exists:", fs.existsSync(path.dirname(DB_PATH))); } catch {}
app.listen(PORT, HOST, ()=>console.log(`Server listening on http://${HOST}:${PORT}`));

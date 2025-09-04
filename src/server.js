// src/server.js
import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import path from "node:path";
import fs from "node:fs";
import process from "node:process";

import db, { DB_PATH } from "./db.js";

const app = express();

// --- Basic security & JSON ---
app.use(helmet());
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.set("trust proxy", 1);

// --- CORS (lock to your site if set) ---
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";
app.use(
  cors({
    origin: CORS_ORIGIN === "*" ? true : [CORS_ORIGIN],
    credentials: true,
  })
);

// --- Logging ---
app.use(morgan("combined"));

// --- Health ---
app.get("/health", (req, res) => {
  try {
    // Tiny db check
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

// --- Example root ---
app.get("/", (req, res) => {
  res.type("text/plain").send("MailSentinel.ai backend is running");
});

// --- 404 fallback ---
app.use((req, res) => res.status(404).json({ error: "Not found" }));

// --- Global error handler ---
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ error: "Internal Server Error" });
});

// --- Start server ---
const PORT = Number(process.env.PORT || 3000);
const HOST = "0.0.0.0";

// Extra startup logs to diagnose crashes
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

// Graceful crash logs
process.on("unhandledRejection", (reason) => {
  console.error("Unhandled Rejection:", reason);
});
process.on("uncaughtException", (err) => {
  console.error("Uncaught Exception:", err);
});

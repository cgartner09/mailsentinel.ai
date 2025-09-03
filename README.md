# MailSentinel.ai — AI Email Security (Software)

This is the **software/backend** for MailSentinel.ai. It scans emails, flags threats, quarantines risky items, sends alerts, and provides a minimal dashboard (with login + TOTP 2FA) to review/release.

> Your **marketing website** is separate (Next.js on Vercel). This repo is the product logic & dashboard.

## Quick Start

```bash
cp .env.example .env   # fill values (SESSION_SECRET, DATA_KEY_HEX, ADMIN_* at least)
npm i
npm run db:reset       # creates sqlite db, admin user, tables
npm run dev

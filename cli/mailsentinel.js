#!/usr/bin/env node
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { annotate, scanEmail } from '../src/scanners.js';
import { parseRawEmail } from '../src/utils/parseEmail.js';
import { quarantineMessage } from '../src/quarantine.js';
import { initDb } from '../src/db.js';

await initDb();

const args = process.argv.slice(2);
const getArg = (k) => {
  const i = args.indexOf(k);
  return i >= 0 ? args[i + 1] : null;
};

const file = getArg('--file');
const dir = getArg('--dir');

async function handleRaw(raw, source = 'upload') {
  const parsed = parseRawEmail(raw);
  const annotated = annotate({ ...parsed, source });
  const { verdict, score, reasons } = await scanEmail({ headers: parsed.headers, subject: parsed.subject, body: parsed.text });
  console.log(`[${annotated.id}] verdict=${verdict} score=${score}`, reasons.join(' | '));
  if (verdict !== 'clean') {
    await quarantineMessage({ ...annotated, verdict, score });
  }
}

if (file) {
  const raw = fs.readFileSync(file, 'utf8');
  await handleRaw(raw, 'upload');
} else if (dir) {
  const files = fs.readdirSync(dir).filter(f => f.endsWith('.eml'));
  for (const f of files) {
    const raw = fs.readFileSync(path.join(dir, f), 'utf8');
    await handleRaw(raw, 'upload');
  }
} else {
  console.log('Usage: node cli/mailsentinel.js --file <email.eml> | --dir <folder>');
}

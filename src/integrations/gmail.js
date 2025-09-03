/**
 * Gmail integration scaffold:
 * - exchange refresh token -> access token
 * - list messages
 * - fetch raw message (RFC822)
 * - parse, scan, quarantine
 *
 * Fill GOOGLE_* envs in .env and implement fetch calls.
 */
import axios from 'axios';
import { parseRawEmail } from '../utils/parseEmail.js';
import { annotate, scanEmail } from '../scanners.js';
import { quarantineMessage } from '../quarantine.js';

async function getAccessToken() {
  // Use OAuth refresh token to get access token
  // https://developers.google.com/identity/protocols/oauth2
  return null; // TODO implement
}

export async function pollGmail() {
  const token = await getAccessToken();
  if (!token) return;

  // 1) list messages, 2) fetch raw RFC822, 3) parse + scan + quarantine
  // This is a scaffold for you to finish when credentials are ready.
}

export async function scanAndQuarantineRawGmail(rfc822) {
  const parsed = parseRawEmail(rfc822);
  const annotated = annotate({ ...parsed, source: 'gmail' });
  const { verdict, score } = await scanEmail({ headers: parsed.headers, subject: parsed.subject, body: parsed.text });
  if (verdict !== 'clean') {
    await quarantineMessage({ ...annotated, verdict, score });
  }
}

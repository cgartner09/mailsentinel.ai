/**
 * Microsoft Graph (Outlook) scaffold:
 * - exchange refresh token -> access token
 * - list messages, fetch MIME content
 */
import axios from 'axios';
import { parseRawEmail } from '../utils/parseEmail.js';
import { annotate, scanEmail } from '../scanners.js';
import { quarantineMessage } from '../quarantine.js';

async function getAccessToken() {
  // Use tenant/client secret to get token
  return null; // TODO implement
}

export async function pollOutlook() {
  const token = await getAccessToken();
  if (!token) return;
  // TODO: list, fetch, scan, quarantine
}

export async function scanAndQuarantineRawOutlook(rfc822) {
  const parsed = parseRawEmail(rfc822);
  const annotated = annotate({ ...parsed, source: 'outlook' });
  const { verdict, score } = await scanEmail({ headers: parsed.headers, subject: parsed.subject, body: parsed.text });
  if (verdict !== 'clean') {
    await quarantineMessage({ ...annotated, verdict, score });
  }
}

import { Router } from 'express';
import multer from 'multer';
import { parseRawEmail } from '../utils/parseEmail.js';
import { annotate, scanEmail } from '../scanners.js';
import { quarantineMessage, releaseMessage, deleteMessage } from '../quarantine.js';
import { getMessage, listMessages } from '../db.js';
import { nanoid } from 'nanoid';

const upload = multer();
const r = Router();

// Upload raw .eml to scan
r.post('/scan', upload.single('eml'), async (req, res) => {
  try {
    const rawStr = req.file ? req.file.buffer.toString('utf8') : (req.body.raw || '');
    if (!rawStr) return res.status(400).json({ error: 'No data' });
    const parsed = parseRawEmail(rawStr);
    const annotated = annotate(parsed);
    const { verdict, score, reasons } = await scanEmail({ headers: parsed.headers, subject: parsed.subject, body: parsed.text });
    if (verdict !== 'clean') {
      await quarantineMessage({ ...annotated, verdict, score });
    }
    res.json({ verdict, score, reasons, id: annotated.id });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'scan_failed' });
  }
});

r.get('/quarantine', (req, res) => {
  const items = listMessages({ quarantine: true });
  res.json(items);
});

r.get('/message/:id', (req, res) => {
  const msg = getMessage(req.params.id);
  if (!msg) return res.status(404).json({ error: 'not_found' });
  res.json(msg);
});

r.post('/message/:id/release', (req, res) => {
  releaseMessage(req.params.id, { actor: 'api' });
  res.json({ ok: true });
});

r.post('/message/:id/delete', (req, res) => {
  deleteMessage(req.params.id, { actor: 'api' });
  res.json({ ok: true });
});

export default r;

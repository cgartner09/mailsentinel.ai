import { Router } from 'express';
import { db } from '../db.js';
import { listMessages, getMessage } from '../db.js';
import { releaseMessage, deleteMessage } from '../quarantine.js';
import { validateUser, verifyTotp, setTotp } from '../auth.js';
import speakeasy from 'speakeasy';
import QRCode from 'qrcode';

const r = Router();

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  next();
}

r.get('/login', (req, res) => {
  res.render('login', { title: 'Login', error: '' });
});

r.post('/login', async (req, res) => {
  const { email, password, token } = req.body;
  const user = await validateUser(email, password);
  if (!user) return res.render('login', { title: 'Login', error: 'Invalid credentials' });

  if (user.totp_secret) {
    if (!token || !verifyTotp(user, token)) {
      return res.render('login', { title: 'Login', error: 'Invalid or missing 2FA code' });
    }
    req.session.userId = user.id;
    return res.redirect('/dashboard');
  }

  // TOTP enrollment
  const secret = speakeasy.generateSecret({ name: 'MailSentinel.ai' });
  const otpauth = secret.otpauth_url;
  const svg = await QRCode.toDataURL(otpauth);
  req.session.tmpUserId = user.id;
  req.session.tmpSecret = secret.base32;
  res.render('totp', { title: 'Set up 2FA', qr: svg });
});

r.post('/totp/verify', (req, res) => {
  const token = req.body.token;
  const uid = req.session.tmpUserId;
  const sec = req.session.tmpSecret;
  if (!uid || !sec) return res.redirect('/login');

  const ok = speakeasy.totp.verify({ secret: sec, encoding: 'base32', token, window: 1 });
  if (!ok) return res.render('totp', { title: 'Set up 2FA', qr: req.body.qr, error: 'Invalid code' });

  setTotp(uid, sec);
  req.session.userId = uid;
  delete req.session.tmpUserId;
  delete req.session.tmpSecret;
  res.redirect('/dashboard');
});

r.get('/dashboard', requireAuth, (req, res) => {
  const items = listMessages({ quarantine: true });
  res.render('dashboard', { title: 'Quarantine', items: JSON.stringify(items) });
});

r.get('/message/:id', requireAuth, (req, res) => {
  const msg = getMessage(req.params.id);
  if (!msg) return res.status(404).send('Not found');
  res.render('message', { title: 'Message', json: JSON.stringify(msg, null, 2), id: msg.id });
});

r.post('/message/:id/release', requireAuth, (req, res) => {
  releaseMessage(req.params.id, { actor: 'dashboard' });
  res.redirect('/dashboard');
});

r.post('/message/:id/delete', requireAuth, (req, res) => {
  deleteMessage(req.params.id, { actor: 'dashboard' });
  res.redirect('/dashboard');
});

r.get('/', (req, res) => res.redirect('/login'));

export default r;

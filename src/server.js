import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import rateLimit from 'express-rate-limit';
import path from 'path';
import { fileURLToPath } from 'url';
import { initDb } from './db.js';
import { ensureAdmin } from './auth.js';
import apiRouter from './routes/api.js';
import dashboardRouter from './routes/dashboard.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

app.use(helmet({
  contentSecurityPolicy: false
}));
app.use(bodyParser.json({ limit: '2mb' }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(session({
  secret: process.env.SESSION_SECRET || 'dev_secret',
  resave: false,
  saveUninitialized: false,
}));

const limiter = rateLimit({ windowMs: 60_000, max: 120 });
app.use(limiter);

app.use('/public', express.static(path.join(__dirname, '..', 'web', 'public')));

app.set('views', path.join(__dirname, '..', 'web', 'views'));
app.engine('html', (path, opts, cb) => {
  import('fs').then(fs => {
    fs.readFile(path, 'utf8', (err, str) => {
      if (err) return cb(err);
      // very tiny template interpolation: {{var}}
      let rendered = str.replace(/\{\{(\w+)\}\}/g, (_, k) => (opts[k] ?? ''));
      cb(null, rendered);
    });
  });
});
app.set('view engine', 'html');

app.use('/api', apiRouter);
app.use('/', dashboardRouter);

const PORT = process.env.PORT || 8080;

await initDb();
await ensureAdmin();

app.listen(PORT, () => {
  console.log(`MailSentinel.ai running on http://localhost:${PORT}`);
});

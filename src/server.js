'use strict';

const express = require('express');
const session = require('express-session');
const passport = require('passport');
const helmet = require('helmet');
const path = require('path');

const config = require('./config');
const { initDb } = require('./db');
const { configurePassport } = require('./auth');
const { requireAuth } = require('./middleware');

const authRouter = require('./routes/auth');
const foldersRouter = require('./routes/folders');
const itemsRouter = require('./routes/items');
const ldapRouter = require('./routes/ldap');
const auditRouter = require('./routes/audit');

const app = express();

// Initialize DB
initDb(config.dbPath, config.rootFolderName);

// Trust proxy (needed for secure cookies behind nginx/traefik)
if (config.trustProxy) app.set('trust proxy', 1);

// Security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      scriptSrcAttr: ["'unsafe-inline'"], // allows onclick="..." in HTML
      styleSrc: ["'self'", "'unsafe-inline'"],
      fontSrc: ["'self'"],
      imgSrc: ["'self'", "data:"],        // allows data: URI favicons
    },
  },
}));

// Favicon — inline SVG so no extra file needed
app.get('/favicon.ico', (req, res) => {
  res.setHeader('Content-Type', 'image/svg+xml');
  res.setHeader('Cache-Control', 'public, max-age=86400');
  res.send('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="6" fill="#6366f1"/><rect x="9" y="14" width="14" height="11" rx="2" fill="#fff"/><path d="M12 14v-3a4 4 0 018 0v3" stroke="#fff" stroke-width="2" stroke-linecap="round" fill="none"/><circle cx="16" cy="19" r="1.5" fill="#6366f1"/><line x1="16" y1="20.5" x2="16" y2="22.5" stroke="#6366f1" stroke-width="1.5" stroke-linecap="round"/></svg>');
});

// Static files (manifest, service worker, icons)
app.use(express.static(path.join(__dirname, 'public')));

// Body parsing
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Sessions
app.use(session({
  secret: config.sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: config.nodeEnv === 'production',
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 8 * 60 * 60 * 1000,
  },
}));

// Passport
app.use(passport.initialize());
app.use(passport.session());
configurePassport(passport);

// Views
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Routes
app.use('/', authRouter);
app.use('/api/folders', foldersRouter);
app.use('/api', itemsRouter);
app.use('/api/ldap', ldapRouter);
app.use('/api', auditRouter);

app.get('/', requireAuth, (req, res) => res.redirect('/app'));
app.get('/app', requireAuth, (req, res) => res.render('app', { user: req.user }));

// Error handler
app.use((err, req, res, _next) => {
  console.error(err);
  const status = err.status || 500;
  if (req.path.startsWith('/api/')) {
    res.status(status).json({ error: err.message || 'Internal server error' });
  } else {
    res.status(status).send(err.message || 'Internal server error');
  }
});

app.listen(config.port, () => {
  console.log(`Server listening on port ${config.port}`);
});

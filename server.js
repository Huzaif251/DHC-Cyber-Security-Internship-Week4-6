// server.js
// DHC Cybersecurity Internship — Week 5
// Author: Abdul Muqeet Tabraiz

require('dotenv').config();
const express = require('express');
const path = require('path');
const session = require('express-session');
const csrf = require('csurf');

const { logger, securityLogger } = require('./config/logger');
const securityHeaders = require('./middleware/securityHeaders');
const { corsMiddleware, corsErrorHandler } = require('./middleware/corsConfig');
const { globalLimiter } = require('./middleware/rateLimiter');
const authRoutes = require('./routes/authRoutes');
const apiRoutes = require('./routes/apiRoutes');

const app = express();
const PORT = process.env.PORT || 3000;

// ════════════════════════════════════════════
// MIDDLEWARE (Order matters!)
// ════════════════════════════════════════════
app.use(securityHeaders);
app.use(corsMiddleware);
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(globalLimiter);
app.use(express.static(path.join(__dirname, 'public')));

// ════════════════════════════════════════════
// SESSION SETUP (Required for CSRF)
// ════════════════════════════════════════════
app.use(session({
    secret: process.env.SESSION_SECRET || 'dhc-cybersecurity-secret-key-2026',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false, // Set to true if using HTTPS
        httpOnly: true,
        maxAge: 3600000 // 1 hour
    }
}));

// ════════════════════════════════════════════
// CSRF PROTECTION - Apply to ALL routes that need it
// ════════════════════════════════════════════
// Initialize CSRF protection middleware
const csrfProtection = csrf({ cookie: false });

// Apply CSRF protection to routes that need it
// We'll apply it to specific routes rather than globally

// Request logger
app.use((req, res, next) => {
    logger.info('REQUEST', { method: req.method, path: req.path, ip: req.ip });
    next();
});

// ════════════════════════════════════════════
// ROUTES
// ════════════════════════════════════════════
// Apply CSRF protection to auth routes (POST methods only)
app.use('/auth', (req, res, next) => {
    if (req.method === 'POST') {
        csrfProtection(req, res, next);
    } else {
        next();
    }
});
app.use('/auth', authRoutes);

// For API routes, we need CSRF token endpoint to work BEFORE protection
// So we'll handle the CSRF token endpoint separately
app.use('/api', (req, res, next) => {
    // Skip CSRF protection for GET /csrf-token
    if (req.path === '/csrf-token' && req.method === 'GET') {
        return next();
    }
    // Apply CSRF protection to other POST/PUT/DELETE routes
    if (['POST', 'PUT', 'DELETE'].includes(req.method)) {
        csrfProtection(req, res, next);
    } else {
        next();
    }
});
app.use('/api', apiRoutes);

// Serve the main dashboard
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ════════════════════════════════════════════
// ERROR HANDLERS
// ════════════════════════════════════════════
app.use(corsErrorHandler);

// CSRF Error Handler
app.use((err, req, res, next) => {
    if (err.code === 'EBADCSRFTOKEN') {
        securityLogger.warn('CSRF_TOKEN_INVALID', {
            ip: req.ip,
            path: req.path,
            error: 'Invalid CSRF token'
        });
        return res.status(403).json({
            status: 403,
            error: 'Forbidden',
            message: 'Invalid CSRF token. Please refresh the page and try again.'
        });
    }
    next(err);
});

// 404 Handler
app.use((req, res) => {
    res.status(404).json({
        status: 404,
        error: 'Not Found',
        message: `${req.method} ${req.path} not found.`
    });
});

// Global Error Handler
app.use((err, req, res, next) => {
    securityLogger.error('SERVER_ERROR', {
        message: err.message,
        ip: req.ip,
        stack: err.stack
    });
    res.status(500).json({
        status: 500,
        error: 'Internal Server Error',
        message: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

// ════════════════════════════════════════════
// START SERVER
// ════════════════════════════════════════════
app.listen(PORT, () => {
    console.log('');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('  DHC Cybersecurity Internship | Week 5 Server');
    console.log('  Author  : Abdul Muqeet Tabraiz');
    console.log(`  Server  : http://localhost:${PORT}`);
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('');
    console.log('  Week 5 Security Features Active:');
    console.log('  ✅  Rate Limiting    (express-rate-limit)');
    console.log('  ✅  CORS Policy      (cors)');
    console.log('  ✅  API Key Auth     (custom middleware)');
    console.log('  ✅  JWT Auth         (jsonwebtoken)');
    console.log('  ✅  CSP Headers      (helmet)');
    console.log('  ✅  HSTS             (helmet)');
    console.log('  ✅  Security Logging (winston)');
    console.log('  ✅  CSRF Protection  (csurf)');
    console.log('  ✅  Session Mgmt     (express-session)');
    console.log('');
    console.log('  Available Endpoints:');
    console.log('  POST  /auth/signup          → Register new user (CSRF protected)');
    console.log('  POST  /auth/login           → Login (CSRF protected)');
    console.log('  GET   /api/csrf-token       → Get CSRF token');
    console.log('  GET   /api/health           → Server health check');
    console.log('  GET   /api/headers-check    → View security headers');
    console.log('  GET   /api/profile          → JWT protected');
    console.log('  GET   /api/data             → API Key protected');
    console.log('  GET   /api/admin            → API Key + JWT + Admin');
    console.log('');
    console.log('  Default admin: admin@dhc.com / Admin@2026');
    console.log('  API Key:       dhc-apikey-admin-001');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('');
    logger.info('Server started', { port: PORT });
});

module.exports = app;
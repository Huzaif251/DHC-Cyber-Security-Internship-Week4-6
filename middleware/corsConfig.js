// middleware/corsConfig.js
// Week 4: CORS — Restrict access to approved origins only
const cors = require('cors');
const { securityLogger } = require('../config/logger');

const corsOptions = {
  origin(origin, callback) {
    const allowed = (process.env.ALLOWED_ORIGINS || 'http://localhost:3000')
      .split(',').map(o => o.trim());
    // Allow Postman/curl (no origin header)
    if (!origin) return callback(null, true);
    if (allowed.includes(origin)) {
      callback(null, true);
    } else {
      securityLogger.warn('CORS_BLOCKED', { blockedOrigin: origin });
      callback(new Error(`CORS: Origin '${origin}' not permitted.`));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
  credentials: true,
  optionsSuccessStatus: 204
};

const corsErrorHandler = (err, req, res, next) => {
  if (err.message && err.message.startsWith('CORS:'))
    return res.status(403).json({ status: 403, error: 'CORS Violation', message: err.message });
  next(err);
};

module.exports = { corsMiddleware: cors(corsOptions), corsErrorHandler };

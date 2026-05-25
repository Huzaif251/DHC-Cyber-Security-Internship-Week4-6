// middleware/auth.js
// Week 4: Authentication — API Key + JWT Bearer Token

const jwt = require('jsonwebtoken');
const { securityLogger } = require('../config/logger');

// ── API KEY AUTH ──────────────────────────────────────────────
const apiKeyAuth = (req, res, next) => {
  const key = req.headers['x-api-key'];
  if (!key) {
    securityLogger.warn('API_KEY_MISSING', { ip: req.ip, path: req.path });
    return res.status(401).json({ status: 401, error: 'Unauthorized', message: 'X-API-Key header required.' });
  }
  const valid = (process.env.VALID_API_KEYS || '').split(',').map(k => k.trim());
  if (!valid.includes(key)) {
    securityLogger.warn('INVALID_API_KEY', { ip: req.ip, keyHint: '***' + key.slice(-4) });
    return res.status(403).json({ status: 403, error: 'Forbidden', message: 'Invalid API key.' });
  }
  req.apiKeyValid = true;
  next();
};

// ── JWT AUTH ──────────────────────────────────────────────────
const jwtAuth = (req, res, next) => {
  const auth = req.headers['authorization'];
  if (!auth || !auth.startsWith('Bearer ')) {
    securityLogger.warn('JWT_MISSING', { ip: req.ip, path: req.path });
    return res.status(401).json({ status: 401, error: 'Unauthorized', message: 'Authorization: Bearer <token> required.' });
  }
  try {
    req.user = jwt.verify(auth.split(' ')[1], process.env.JWT_SECRET);
    next();
  } catch (err) {
    securityLogger.warn('JWT_INVALID', { ip: req.ip, error: err.message });
    if (err.name === 'TokenExpiredError')
      return res.status(401).json({ status: 401, error: 'Token Expired', message: 'Session expired. Please login again.' });
    return res.status(403).json({ status: 403, error: 'Forbidden', message: 'Invalid token.' });
  }
};

// ── DUAL AUTH ─────────────────────────────────────────────────
const fullAuth = [apiKeyAuth, jwtAuth];

module.exports = { apiKeyAuth, jwtAuth, fullAuth };

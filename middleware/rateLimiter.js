// middleware/rateLimiter.js
// Week 4: Rate Limiting — Brute-force & DDoS protection
const rateLimit = require('express-rate-limit');
const { securityLogger } = require('../config/logger');

// Global: 100 requests per 15 minutes
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  handler(req, res, next, options) {
    securityLogger.warn('RATE_LIMIT_EXCEEDED_GLOBAL', { ip: req.ip, path: req.path });
    res.status(429).json({ status: 429, error: 'Too Many Requests', message: 'Rate limit exceeded. Try again in 15 minutes.' });
  }
});

// Login: 5 attempts per 15 minutes (Fail2Ban-style)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: parseInt(process.env.LOGIN_RATE_LIMIT_MAX) || 5,
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  handler(req, res, next, options) {
    securityLogger.warn('BRUTE_FORCE_DETECTED', {
      ip: req.ip,
      email: req.body?.email || 'unknown',
      alert: 'Possible brute-force attack on /login'
    });
    res.status(429).json({
      status: 429,
      error: 'Too Many Login Attempts',
      message: 'Account locked due to multiple failed login attempts. Try again in 15 minutes.'
    });
  }
});

// API routes: 200 requests per 15 minutes
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  handler(req, res, next, options) {
    securityLogger.warn('RATE_LIMIT_EXCEEDED_API', { ip: req.ip, path: req.path });
    res.status(429).json({ status: 429, error: 'API Rate Limit Exceeded' });
  }
});

module.exports = { globalLimiter, loginLimiter, apiLimiter };

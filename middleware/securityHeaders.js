// middleware/securityHeaders.js
// Week 4: Security Headers — Content Security Policy + HSTS
const helmet = require('helmet');

const securityHeaders = helmet({
  // CONTENT SECURITY POLICY — prevents XSS / script injection
  contentSecurityPolicy: {
    directives: {
      defaultSrc:  ["'self'"],
      scriptSrc:   ["'self'", "'unsafe-inline'"],   // unsafe-inline needed for dashboard
      styleSrc:    ["'self'", "'unsafe-inline'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      imgSrc:      ["'self'", "data:", "https:"],
      objectSrc:   ["'none'"],
      frameSrc:    ["'none'"],
      baseUri:     ["'self'"],
      formAction:  ["'self'"],
    }
  },

  // HTTP STRICT TRANSPORT SECURITY — forces HTTPS for 1 year
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },

  // X-FRAME-OPTIONS — prevents clickjacking
  frameguard: { action: 'deny' },

  // X-CONTENT-TYPE-OPTIONS — prevents MIME sniffing
  noSniff: true,

  // REFERRER POLICY
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },

  // HIDE X-POWERED-BY — don't reveal Express
  hidePoweredBy: true,

  crossOriginOpenerPolicy: { policy: 'same-origin' },
  crossOriginEmbedderPolicy: false
});

module.exports = securityHeaders;

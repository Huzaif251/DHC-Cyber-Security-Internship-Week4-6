// middleware/csrfHelper.js
// Simple CSRF token generator for Week 5

const crypto = require('crypto');

// Store tokens in memory (in production, use Redis or database)
const tokenStore = new Map();

// Clean up expired tokens every hour
setInterval(() => {
    const now = Date.now();
    for (const [token, data] of tokenStore.entries()) {
        if (data.expires < now) {
            tokenStore.delete(token);
        }
    }
}, 3600000);

const generateCsrfToken = (sessionId) => {
    const token = crypto.randomBytes(32).toString('hex');
    const expires = Date.now() + 3600000; // 1 hour expiry
    
    tokenStore.set(token, {
        sessionId,
        expires,
        createdAt: Date.now()
    });
    
    return token;
};

const validateCsrfToken = (token, sessionId) => {
    const stored = tokenStore.get(token);
    if (!stored) return false;
    if (stored.sessionId !== sessionId) return false;
    if (stored.expires < Date.now()) {
        tokenStore.delete(token);
        return false;
    }
    return true;
};

const csrfMiddleware = (req, res, next) => {
    // Generate token for GET requests
    if (req.method === 'GET') {
        const sessionId = req.sessionID;
        const token = generateCsrfToken(sessionId);
        res.locals.csrfToken = token;
        req.csrfToken = () => token;
        return next();
    }
    
    // Validate token for POST/PUT/DELETE
    if (['POST', 'PUT', 'DELETE'].includes(req.method)) {
        const token = req.body._csrf || req.headers['x-csrf-token'];
        const sessionId = req.sessionID;
        
        if (!token || !validateCsrfToken(token, sessionId)) {
            return res.status(403).json({
                status: 403,
                error: 'Forbidden',
                message: 'Invalid CSRF token'
            });
        }
    }
    
    next();
};

module.exports = { csrfMiddleware, generateCsrfToken, validateCsrfToken };
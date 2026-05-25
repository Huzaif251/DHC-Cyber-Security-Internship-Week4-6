// routes/apiRoutes.js
// Week 5: API Routes with CSRF token endpoint

const express = require('express');
const router = express.Router();
const { apiKeyAuth, jwtAuth, fullAuth } = require('../middleware/auth');
const { apiLimiter } = require('../middleware/rateLimiter');
const { securityLogger } = require('../config/logger');
const db = require('../config/database');

// Apply rate limiting to all API routes
router.use(apiLimiter);

// ── CSRF Token Endpoint (Week 5) ─────────────────────────────────
// IMPORTANT: This route must NOT have CSRF protection applied
router.get('/csrf-token', (req, res) => {
    try {
        // The csrfToken function should be attached by the csurf middleware
        // But since we're not applying CSRF to GET requests, we need to manually generate
        // We'll use a different approach: create a temporary CSRF protection instance
        
        // For the token endpoint, we need to generate a token without validating one
        // We can do this by using the csrfProtection middleware but then immediately calling next
        
        // Alternative: Use the csrf() function to generate a token
        // But since we don't have req.csrfToken available, we need to add it
        
        if (!req.csrfToken) {
            // If csrfToken is not available, we need to initialize it for this route
            const csrf = require('csurf');
            const csrfProtection = csrf({ cookie: false });
            
            // Apply csrf protection to get the token function, but don't validate
            csrfProtection(req, res, () => {
                // After this, req.csrfToken should be available
                const token = req.csrfToken();
                securityLogger.info('CSRF_TOKEN_GENERATED', { ip: req.ip });
                res.json({
                    status: 200,
                    csrfToken: token,
                    message: 'CSRF token generated successfully'
                });
            });
        } else {
            // If csrfToken is already available
            const token = req.csrfToken();
            securityLogger.info('CSRF_TOKEN_GENERATED', { ip: req.ip });
            res.json({
                status: 200,
                csrfToken: token,
                message: 'CSRF token generated successfully'
            });
        }
    } catch (error) {
        securityLogger.error('CSRF_TOKEN_ERROR', {
            ip: req.ip,
            error: error.message,
            stack: error.stack
        });
        res.status(500).json({
            status: 500,
            error: 'Internal Server Error',
            message: 'Failed to generate CSRF token: ' + error.message
        });
    }
});

// ── Health Check (Public) ──────────────────────────────────────
router.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        security: {
            rateLimiting: 'active',
            csrf: 'active',
            cors: 'active',
            apiKey: 'active',
            jwt: 'active',
            headers: 'active'
        }
    });
});

// ── Security Headers Check ─────────────────────────────────────
router.get('/headers-check', (req, res) => {
    res.json({
        message: 'Security Headers Active',
        headers: {
            'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'",
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
            'X-Frame-Options': 'DENY',
            'X-Content-Type-Options': 'nosniff',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'X-Powered-By': 'removed'
        }
    });
});

// ── Profile (JWT Protected) ────────────────────────────────────
router.get('/profile', jwtAuth, (req, res) => {
    res.json({
        status: 200,
        user: {
            id: req.user.id,
            email: req.user.email,
            role: req.user.role
        }
    });
});

// ── Data (API Key Protected) ───────────────────────────────────
router.get('/data', apiKeyAuth, (req, res) => {
    res.json({
        status: 200,
        message: 'Sensitive data accessed with API key',
        data: {
            secret: 'This is protected by API key authentication',
            timestamp: new Date().toISOString()
        }
    });
});

// ── Admin (Full Authentication: API Key + JWT) ─────────────────
router.get('/admin', fullAuth, (req, res) => {
    if (req.user.role !== 'admin') {
        securityLogger.warn('ADMIN_ACCESS_DENIED', {
            ip: req.ip,
            user: req.user.email,
            role: req.user.role
        });
        return res.status(403).json({
            status: 403,
            error: 'Forbidden',
            message: 'Admin access required'
        });
    }

    res.json({
        status: 200,
        message: 'Admin panel accessed',
        admin: {
            user: req.user,
            permissions: ['read', 'write', 'delete', 'admin'],
            timestamp: new Date().toISOString()
        }
    });
});

// ── Get Audit Log (Admin only) ─────────────────────────────────
router.get('/audit-log', fullAuth, async (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({
            status: 403,
            error: 'Forbidden',
            message: 'Admin access required'
        });
    }

    try {
        const logs = await db.getAuditLog();
        res.json({
            status: 200,
            logs: logs
        });
    } catch (error) {
        securityLogger.error('AUDIT_LOG_ERROR', { error: error.message });
        res.status(500).json({
            status: 500,
            error: 'Failed to fetch audit logs'
        });
    }
});

module.exports = router;
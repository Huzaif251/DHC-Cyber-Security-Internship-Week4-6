// routes/authRoutes.js
// Week 5: Authentication Routes with CSRF protection

const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { loginLimiter } = require('../middleware/rateLimiter');
const { securityLogger } = require('../config/logger');
const db = require('../config/database');
const validator = require('validator');

// Login route with CSRF protection and rate limiting
router.post('/login', loginLimiter, async (req, res) => {
    try {
        const { email, password, _csrf } = req.body;

        // Input validation
        if (!email || !password) {
            return res.status(400).json({
                status: 400,
                error: 'Bad Request',
                message: 'Email and password are required'
            });
        }

        // Find user by email (using prepared statement)
        const user = await db.findByEmail(email);

        if (!user) {
            securityLogger.warn('LOGIN_FAILED', {
                ip: req.ip,
                email: email,
                reason: 'User not found'
            });
            return res.status(401).json({
                status: 401,
                error: 'Unauthorized',
                message: 'Invalid credentials'
            });
        }

        // Verify password
        const isValid = await bcrypt.compare(password, user.password);

        if (!isValid) {
            securityLogger.warn('LOGIN_FAILED', {
                ip: req.ip,
                email: email,
                reason: 'Invalid password'
            });
            return res.status(401).json({
                status: 401,
                error: 'Unauthorized',
                message: 'Invalid credentials'
            });
        }

        // Generate JWT token
        const token = jwt.sign(
            {
                id: user.id,
                email: user.email,
                role: user.role
            },
            process.env.JWT_SECRET || 'dhc-jwt-secret-key-2026',
            { expiresIn: '1h' }
        );

        // Log successful login
        await db.logAction(user.id, 'LOGIN_SUCCESS', req.ip);
        securityLogger.info('LOGIN_SUCCESS', {
            ip: req.ip,
            user: user.email,
            role: user.role
        });

        res.json({
            status: 200,
            message: 'Login successful',
            token: token,
            user: {
                id: user.id,
                email: user.email,
                role: user.role
            }
        });

    } catch (error) {
        securityLogger.error('LOGIN_ERROR', {
            ip: req.ip,
            error: error.message
        });
        res.status(500).json({
            status: 500,
            error: 'Internal Server Error'
        });
    }
});

// Signup route with CSRF protection
router.post('/signup', async (req, res) => {
    try {
        const { email, password, _csrf } = req.body;

        // Validate input
        if (!email || !password) {
            return res.status(400).json({
                status: 400,
                error: 'Bad Request',
                message: 'Email and password are required'
            });
        }

        if (!validator.isEmail(email)) {
            return res.status(400).json({
                status: 400,
                error: 'Bad Request',
                message: 'Invalid email format'
            });
        }

        if (password.length < 6) {
            return res.status(400).json({
                status: 400,
                error: 'Bad Request',
                message: 'Password must be at least 6 characters'
            });
        }

        // Check if user already exists
        const existingUser = await db.findByEmail(email);
        if (existingUser) {
            return res.status(409).json({
                status: 409,
                error: 'Conflict',
                message: 'User already exists'
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 12);

        // Create user
        const newUser = await db.createUser(email, hashedPassword, 'user');

        // Log signup
        await db.logAction(newUser.id, 'SIGNUP_SUCCESS', req.ip);
        securityLogger.info('SIGNUP_SUCCESS', {
            ip: req.ip,
            email: email
        });

        res.status(201).json({
            status: 201,
            message: 'User created successfully',
            user: {
                id: newUser.id,
                email: email,
                role: 'user'
            }
        });

    } catch (error) {
        securityLogger.error('SIGNUP_ERROR', {
            ip: req.ip,
            error: error.message
        });
        res.status(500).json({
            status: 500,
            error: 'Internal Server Error'
        });
    }
});

module.exports = router;
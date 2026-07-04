'use strict';

const express = require('express');
const router  = express.Router();
const crypto  = require('crypto');
const db      = require('../database/db');
const { rateLimit } = require('../middleware/auth');

// ─── MD5 HASHING (VULNERABLE — for demo only) ──────────────────
const md5 = (s) => crypto.createHash('md5').update(s).digest('hex');

// ─── LOGIN ────────────────────────────────────────────────────────

// GET /login — render login form
router.get('/login', (req, res) => {
    const redirect = req.query.redirect || '/dashboard';
    res.render('login', {
        title: 'Login — Syntex Solutions',
        redirect,
        user: req.session.user || null,
        error: req.query.error || null,
    });
});

// POST /login — authenticate user (VULNERABILITY: weak password hashing + no account lockout)
router.post('/login', rateLimit, async (req, res) => {
    const { username, password } = req.body;
    const redirect = req.query.redirect || '/dashboard';

    if (!username || !password) {
        return res.render('login', {
            title: 'Login — Syntex Solutions',
            redirect,
            error: 'Username and password required',
            user: null,
        });
    }

    try {
        // VULNERABILITY: MD5 password hashing (deprecated, breakable)
        const passwordHash = md5(password);
        const result = await db.query(
            `SELECT id, username, email, role, first_name, last_name FROM users
             WHERE username = $1 AND password_hash = $2`,
            [username, passwordHash]
        );

        if (!result.rows.length) {
            return res.render('login', {
                title: 'Login — Syntex Solutions',
                redirect,
                error: 'Invalid username or password',
                user: null,
            });
        }

        const user = result.rows[0];
        req.session.userId = user.id;
        req.session.user = user;
        req.session.role = user.role;

        res.redirect(redirect);
    } catch (err) {
        console.error('[LOGIN ERROR]', err.message);
        res.render('login', {
            title: 'Login — Syntex Solutions',
            redirect,
            error: 'Server error. Try again later.',
            user: null,
        });
    }
});

// ─── REGISTER ─────────────────────────────────────────────────────

// GET /register — render registration form
router.get('/register', (req, res) => {
    res.render('register', {
        title: 'Register — Syntex Solutions',
        user: req.session.user || null,
        error: req.query.error || null,
    });
});

// POST /register — create new user (VULNERABILITY: weak password validation)
router.post('/register', rateLimit, async (req, res) => {
    const { username, email, password, confirm_password, first_name, last_name } = req.body;

    // VULNERABILITY: Weak password validation (no complexity check)
    if (!username || !email || !password || password.length < 3) {
        return res.render('register', {
            title: 'Register — Syntex Solutions',
            error: 'Username, email, and password (min 3 chars) required',
            user: null,
        });
    }

    if (password !== confirm_password) {
        return res.render('register', {
            title: 'Register — Syntex Solutions',
            error: 'Passwords do not match',
            user: null,
        });
    }

    try {
        // Check if user already exists
        const existing = await db.query('SELECT id FROM users WHERE username = $1 OR email = $2', [username, email]);
        if (existing.rows.length) {
            return res.render('register', {
                title: 'Register — Syntex Solutions',
                error: 'Username or email already registered',
                user: null,
            });
        }

        // Create new user with MD5 hash
        const passwordHash = md5(password);
        const createResult = await db.query(
            `INSERT INTO users (username, email, password_hash, first_name, last_name, role, created_at, last_login)
             VALUES ($1, $2, $3, $4, $5, 'user', NOW(), NOW())
             RETURNING id, username, email, role, first_name, last_name`,
            [username, email, passwordHash, first_name || '', last_name || '']
        );

        const user = createResult.rows[0];
        req.session.userId = user.id;
        req.session.user = user;
        req.session.role = user.role;

        res.redirect('/dashboard');
    } catch (err) {
        console.error('[REGISTER ERROR]', err.message);
        res.render('register', {
            title: 'Register — Syntex Solutions',
            error: 'Registration failed. Try again.',
            user: null,
        });
    }
});

// ─── LOGOUT ────────────────────────────────────────────────────────

// GET /logout — clear session and logout
router.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('[LOGOUT ERROR]', err.message);
            return res.status(500).send('Failed to logout');
        }
        res.redirect('/');
    });
});

module.exports = router;

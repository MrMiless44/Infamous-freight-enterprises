const express = require('express');
const { limiters, authenticate, requireScope, auditLog } = require('../middleware/security');
const { validateString, validateEmail, handleValidationErrors } = require('../middleware/validation');

const router = express.Router();

/**
 * GET /api/users/me
 * Get current user profile
 * Scope: users:read
 */
router.get(
    '/users/me',
    limiters.general,
    authenticate,
    requireScope('users:read'),
    auditLog,
    async (req, res, next) => {
        try {
            // Return user from JWT payload
            const user = {
                id: req.user.sub,
                email: req.user.email,
                role: req.user.role,
                scopes: req.user.scopes,
            };

            res.json({
                ok: true,
                user,
            });
        } catch (err) {
            next(err);
        }
    }
);

/**
 * PATCH /api/users/me
 * Update current user profile
 * Scope: users:write
 */
router.patch(
    '/users/me',
    limiters.general,
    authenticate,
    requireScope('users:write'),
    [
        validateString('name', { maxLength: 100 }).optional(),
        validateEmail('email').optional(),
        handleValidationErrors,
    ],
    auditLog,
    async (req, res, next) => {
        try {
            const { name, email } = req.body;

            // TODO: Update user in database
            const user = {
                id: req.user.sub,
                name,
                email,
                updatedAt: new Date().toISOString(),
            };

            res.json({
                ok: true,
                user,
            });
        } catch (err) {
            next(err);
        }
    }
);

/**
 * GET /api/users
 * List all users (admin only)
 * Scope: admin
 */
router.get(
    '/users',
    limiters.general,
    authenticate,
    requireScope('admin'),
    auditLog,
    async (req, res, next) => {
        try {
            // TODO: Fetch from database
            const users = [];

            res.json({
                ok: true,
                users,
                count: users.length,
            });
        } catch (err) {
            next(err);
        }
    }
);

module.exports = router;

/**
 * Shared authentication helpers for tests
 */
const jwt = require('jsonwebtoken')

/**
 * Create a test JWT token with specified scopes
 * @param {string[]} scopes - Array of permission scopes
 * @param {object} options - Additional JWT payload options
 * @returns {string} JWT token
 */
function makeToken(scopes = ['read'], options = {}) {
    const payload = {
        sub: options.sub || 'test-user',
        email: options.email || 'test@example.com',
        roles: options.roles || ['user'],
        scopes,
        iat: options.iat || Math.floor(Date.now() / 1000),
        exp: options.exp || Math.floor(Date.now() / 1000) + 3600, // 1 hour
        ...options.custom
    }

    const secret = process.env.JWT_SECRET || 'test-secret'
    return jwt.sign(payload, secret)
}

/**
 * Create Authorization header with Bearer token
 * @param {string} token - JWT token
 * @returns {object} Headers object
 */
function authHeader(token) {
    return { Authorization: `Bearer ${token}` }
}

/**
 * Create a test user with specified role
 * @param {string} role - User role (user, admin, driver)
 * @param {object} overrides - Additional user properties
 * @returns {object} User object
 */
function createTestUser(role = 'user', overrides = {}) {
    return {
        id: overrides.id || 'test-user-1',
        email: overrides.email || 'test@example.com',
        name: overrides.name || 'Test User',
        role,
        createdAt: overrides.createdAt || new Date(),
        updatedAt: overrides.updatedAt || new Date(),
        ...overrides
    }
}

/**
 * Create admin token with all scopes
 * @returns {string} JWT token
 */
function makeAdminToken() {
    return makeToken(
        [
            'read',
            'write',
            'delete',
            'ai:command',
            'voice:ingest',
            'voice:command',
            'billing:read',
            'billing:write',
            'admin:all'
        ],
        { roles: ['admin'], sub: 'admin-user' }
    )
}

/**
 * Create driver token with driver-specific scopes
 * @returns {string} JWT token
 */
function makeDriverToken() {
    return makeToken(
        ['read', 'shipments:read', 'shipments:update', 'voice:command'],
        { roles: ['driver'], sub: 'driver-user' }
    )
}

/**
 * Create an expired token for testing auth failures
 * @returns {string} Expired JWT token
 */
function makeExpiredToken() {
    return makeToken(['read'], {
        iat: Math.floor(Date.now() / 1000) - 7200, // 2 hours ago
        exp: Math.floor(Date.now() / 1000) - 3600 // 1 hour ago
    })
}

module.exports = {
    makeToken,
    authHeader,
    createTestUser,
    makeAdminToken,
    makeDriverToken,
    makeExpiredToken
}

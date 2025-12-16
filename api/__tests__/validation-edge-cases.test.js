const request = require('supertest')
const jwt = require('jsonwebtoken')

process.env.JWT_SECRET = 'test-secret'
delete process.env.STRIPE_SECRET_KEY
delete process.env.PAYPAL_CLIENT_ID

const app = require('../src/server')

const makeToken = (scopes) =>
    jwt.sign(
        {
            sub: 'test-user',
            scopes
        },
        process.env.JWT_SECRET
    )

const authHeader = (token) => `Bearer ${token}`

describe('POST /api/users - Edge Cases', () => {
    describe('Email validation edge cases', () => {
        test('rejects invalid email: no domain', async () => {
            const res = await request(app)
                .post('/api/users')
                .send({
                    email: 'user@',
                    name: 'Test User',
                    role: 'driver'
                })

            expect(res.status).toBe(400)
            expect(res.body.error).toBe('Validation Error')
            expect(res.body.details.some((d) => d.path === 'email')).toBe(true)
        })

        test('rejects invalid email: no local part', async () => {
            const res = await request(app)
                .post('/api/users')
                .send({
                    email: '@example.com',
                    name: 'Test User',
                    role: 'driver'
                })

            expect(res.status).toBe(400)
            expect(res.body.error).toBe('Validation Error')
        })

        test('rejects invalid email: spaces', async () => {
            const res = await request(app)
                .post('/api/users')
                .send({
                    email: 'user @example.com',
                    name: 'Test User',
                    role: 'driver'
                })

            expect(res.status).toBe(400)
            expect(res.body.error).toBe('Validation Error')
        })

        test('rejects invalid email: no TLD', async () => {
            const res = await request(app)
                .post('/api/users')
                .send({
                    email: 'user@localhost',
                    name: 'Test User',
                    role: 'driver'
                })

            expect(res.status).toBe(400)
            expect(res.body.error).toBe('Validation Error')
        })

        test('accepts valid complex email: plus addressing', async () => {
            const res = await request(app)
                .post('/api/users')
                .send({
                    email: 'user+tag@example.co.uk',
                    name: 'Test User',
                    role: 'user'
                })

            expect(res.status).toBe(201)
            expect(res.body.success).toBe(true)
            expect(res.body.data.email).toBe('user+tag@example.co.uk')
        })

        test('accepts valid complex email: subdomain', async () => {
            const res = await request(app)
                .post('/api/users')
                .send({
                    email: 'test@mail.example.com',
                    name: 'Test User',
                    role: 'user'
                })

            expect(res.status).toBe(201)
            expect(res.body.success).toBe(true)
        })
    })

    describe('Name validation edge cases', () => {
        test('rejects name with only whitespace', async () => {
            const res = await request(app)
                .post('/api/users')
                .send({
                    email: 'user@example.com',
                    name: '   ',
                    role: 'driver'
                })

            expect(res.status).toBe(400)
            expect(res.body.error).toBe('Validation Error')
        })

        test('accepts name with leading/trailing spaces (auto-trimmed)', async () => {
            const res = await request(app)
                .post('/api/users')
                .send({
                    email: 'user@example.com',
                    name: '  John Doe  ',
                    role: 'driver'
                })

            expect(res.status).toBe(201)
            expect(res.body.data.name).toBe('John Doe')
        })

        test('rejects name exceeding max length (100 chars)', async () => {
            const longName = 'A'.repeat(101)
            const res = await request(app)
                .post('/api/users')
                .send({
                    email: 'user@example.com',
                    name: longName,
                    role: 'driver'
                })

            expect(res.status).toBe(400)
            expect(res.body.error).toBe('Validation Error')
        })

        test('accepts name at max length boundary (100 chars)', async () => {
            const maxName = 'A'.repeat(100)
            const res = await request(app)
                .post('/api/users')
                .send({
                    email: 'user@example.com',
                    name: maxName,
                    role: 'driver'
                })

            expect(res.status).toBe(201)
            expect(res.body.data.name).toHaveLength(100)
        })

        test('accepts name with special characters', async () => {
            const res = await request(app)
                .post('/api/users')
                .send({
                    email: 'user@example.com',
                    name: "O'Brien-Müller Jr.",
                    role: 'driver'
                })

            expect(res.status).toBe(201)
            expect(res.body.success).toBe(true)
        })

        test('accepts name with numbers', async () => {
            const res = await request(app)
                .post('/api/users')
                .send({
                    email: 'user@example.com',
                    name: 'Agent 007',
                    role: 'driver'
                })

            expect(res.status).toBe(201)
            expect(res.body.success).toBe(true)
        })
    })

    describe('Role validation edge cases', () => {
        test('rejects invalid role: typo', async () => {
            const res = await request(app)
                .post('/api/users')
                .send({
                    email: 'user@example.com',
                    name: 'Test User',
                    role: 'drivr' // typo
                })

            expect(res.status).toBe(400)
            expect(res.body.error).toBe('Validation Error')
            expect(res.body.details.some((d) => d.path === 'role')).toBe(true)
        })

        test('rejects invalid role: uppercase', async () => {
            const res = await request(app)
                .post('/api/users')
                .send({
                    email: 'user@example.com',
                    name: 'Test User',
                    role: 'DRIVER'
                })

            expect(res.status).toBe(400)
            expect(res.body.error).toBe('Validation Error')
        })

        test('rejects invalid role: number', async () => {
            const res = await request(app)
                .post('/api/users')
                .send({
                    email: 'user@example.com',
                    name: 'Test User',
                    role: 1 // number instead of string
                })

            expect(res.status).toBe(400)
            expect(res.body.error).toBe('Validation Error')
        })

        test('accepts valid role: driver', async () => {
            const res = await request(app)
                .post('/api/users')
                .send({
                    email: 'user@example.com',
                    name: 'Test User',
                    role: 'driver'
                })

            expect(res.status).toBe(201)
            expect(res.body.data.role).toBe('driver')
        })

        test('accepts valid role: admin', async () => {
            const res = await request(app)
                .post('/api/users')
                .send({
                    email: 'user@example.com',
                    name: 'Test User',
                    role: 'admin'
                })

            expect(res.status).toBe(201)
            expect(res.body.data.role).toBe('admin')
        })

        test('accepts valid role: user', async () => {
            const res = await request(app)
                .post('/api/users')
                .send({
                    email: 'user@example.com',
                    name: 'Test User',
                    role: 'user'
                })

            expect(res.status).toBe(201)
            expect(res.body.data.role).toBe('user')
        })
    })

    describe('Type coercion edge cases', () => {
        test('rejects email as non-string: number', async () => {
            const res = await request(app)
                .post('/api/users')
                .send({
                    email: 12345,
                    name: 'Test User',
                    role: 'driver'
                })

            expect(res.status).toBe(400)
            expect(res.body.error).toBe('Validation Error')
        })

        test('rejects email as non-string: object', async () => {
            const res = await request(app)
                .post('/api/users')
                .send({
                    email: { address: 'user@example.com' },
                    name: 'Test User',
                    role: 'driver'
                })

            expect(res.status).toBe(400)
            expect(res.body.error).toBe('Validation Error')
        })

        test('rejects email as non-string: array', async () => {
            const res = await request(app)
                .post('/api/users')
                .send({
                    email: ['user@example.com'],
                    name: 'Test User',
                    role: 'driver'
                })

            expect(res.status).toBe(400)
            expect(res.body.error).toBe('Validation Error')
        })

        test('rejects email as non-string: null', async () => {
            const res = await request(app)
                .post('/api/users')
                .send({
                    email: null,
                    name: 'Test User',
                    role: 'driver'
                })

            expect(res.status).toBe(400)
            expect(res.body.error).toBe('Validation Error')
        })

        test('rejects email as non-string: undefined', async () => {
            const res = await request(app)
                .post('/api/users')
                .send({
                    name: 'Test User',
                    role: 'driver'
                })

            expect(res.status).toBe(400)
            expect(res.body.error).toBe('Validation Error')
        })
    })

    describe('Missing fields', () => {
        test('rejects request missing email', async () => {
            const res = await request(app)
                .post('/api/users')
                .send({
                    name: 'Test User',
                    role: 'driver'
                })

            expect(res.status).toBe(400)
        })

        test('allows request missing optional name', async () => {
            const res = await request(app)
                .post('/api/users')
                .send({
                    email: 'user@example.com',
                    role: 'driver'
                })

            expect(res.status).toBe(201)
            expect(res.body.success).toBe(true)
        })

        test('allows request missing optional role', async () => {
            const res = await request(app)
                .post('/api/users')
                .send({
                    email: 'user@example.com',
                    name: 'Test User'
                })

            expect(res.status).toBe(201)
            expect(res.body.success).toBe(true)
        })
    })

    describe('Multiple field errors', () => {
        test('returns all validation errors when multiple fields invalid', async () => {
            const res = await request(app)
                .post('/api/users')
                .send({
                    email: 'invalid-email',
                    name: 'A'.repeat(101),
                    role: 'invalid_role'
                })

            expect(res.status).toBe(400)
            expect(res.body.error).toBe('Validation Error')
            expect(res.body.details.length).toBeGreaterThanOrEqual(3)
            expect(
                res.body.details.map((d) => d.path).includes('email')
            ).toBe(true)
            expect(
                res.body.details.map((d) => d.path).includes('name')
            ).toBe(true)
            expect(
                res.body.details.map((d) => d.path).includes('role')
            ).toBe(true)
        })
    })

    describe('Empty body', () => {
        test('rejects request with empty body', async () => {
            const res = await request(app)
                .post('/api/users')
                .send({})

            expect(res.status).toBe(400)
            expect(res.body.error).toBe('Validation Error')
        })

        test('rejects request with empty JSON object', async () => {
            const res = await request(app)
                .post('/api/users')
                .send({})

            expect(res.status).toBe(400)
        })
    })
})

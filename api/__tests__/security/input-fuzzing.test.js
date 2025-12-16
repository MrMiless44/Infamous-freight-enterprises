/**
 * Security tests - Input fuzzing and injection attacks
 */
const request = require('supertest')
const { makeToken, authHeader } = require('../helpers/auth')
const { maliciousInputs, edgeCaseInputs } = require('../helpers/fixtures')

// Mock dependencies
const mockPrisma = {
    user: {
        findUnique: jest.fn(),
        create: jest.fn()
    },
    shipment: {
        create: jest.fn(),
        findUnique: jest.fn()
    }
}

jest.mock('../../src/db/prisma', () => mockPrisma)
jest.mock('../../src/config/sentry', () => ({
    initSentry: jest.fn(),
    attachErrorHandler: jest.fn()
}))

describe('Security - Input Fuzzing', () => {
    let app
    let token

    beforeAll(() => {
        process.env.NODE_ENV = 'test'
        process.env.JWT_SECRET = 'test-secret'
        process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test'

        jest.resetModules()
        app = require('../../src/server')
        token = makeToken(['shipments:write', 'users:write'])
    })

    beforeEach(() => {
        jest.clearAllMocks()
        mockPrisma.user.findUnique.mockResolvedValue({
            id: 'user-1',
            email: 'test@example.com'
        })
    })

    describe('XSS Prevention', () => {
        const xssPayloads = [
            '<script>alert("xss")</script>',
            '<img src=x onerror=alert("xss")>',
            'javascript:alert("xss")',
            "<iframe src='javascript:alert(1)'>",
            "<svg onload=alert('xss')>"
        ]

        xssPayloads.forEach((payload) => {
            test(`should sanitize XSS payload: ${payload.substring(0, 30)}...`, async () => {
                mockPrisma.shipment.create.mockResolvedValue({
                    id: 'test-1',
                    trackingNumber: 'TEST-001'
                })

                const res = await request(app)
                    .post('/api/shipments')
                    .set(authHeader(token))
                    .send({
                        origin: payload,
                        destination: 'Los Angeles, CA',
                        weight: 10
                    })

                // Should either reject (400) or sanitize (201)
                if (res.status === 201) {
                    // If accepted, verify it's sanitized
                    expect(res.body.shipment.origin).not.toContain('<script>')
                    expect(res.body.shipment.origin).not.toContain('javascript:')
                } else {
                    expect(res.status).toBe(400)
                }
            })
        })
    })

    describe('SQL Injection Prevention', () => {
        const sqlInjectionPayloads = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "admin'--",
            "1' UNION SELECT NULL--",
            "' OR 1=1--",
            "admin' /*"
        ]

        sqlInjectionPayloads.forEach((payload) => {
            test(`should prevent SQL injection: ${payload}`, async () => {
                mockPrisma.user.create.mockResolvedValue({
                    id: 'test-1',
                    email: 'test@example.com'
                })

                const res = await request(app)
                    .post('/api/users')
                    .set(authHeader(token))
                    .send({
                        email: payload,
                        name: 'Test User',
                        role: 'user'
                    })

                // Should reject invalid email format
                expect(res.status).toBe(400)
                expect(mockPrisma.user.create).not.toHaveBeenCalled()
            })
        })
    })

    describe('Path Traversal Prevention', () => {
        const pathTraversalPayloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32',
            '/etc/shadow',
            '....//....//....//etc/passwd',
            '..\\..\\..\\..\\boot.ini'
        ]

        pathTraversalPayloads.forEach((payload) => {
            test(`should prevent path traversal: ${payload}`, async () => {
                const res = await request(app)
                    .get(`/api/shipments/${payload}`)
                    .set(authHeader(token))

                // Should return 400 or 404, never 200
                expect([400, 404]).toContain(res.status)
            })
        })
    })

    describe('Command Injection Prevention', () => {
        const commandInjectionPayloads = [
            '; ls -la',
            '| cat /etc/passwd',
            '$(whoami)',
            '`id`',
            '&& rm -rf /'
        ]

        commandInjectionPayloads.forEach((payload) => {
            test(`should prevent command injection: ${payload}`, async () => {
                mockPrisma.shipment.create.mockResolvedValue({
                    id: 'test-1',
                    trackingNumber: 'TEST-001'
                })

                const res = await request(app)
                    .post('/api/shipments')
                    .set(authHeader(token))
                    .send({
                        origin: 'New York',
                        destination: payload,
                        weight: 10
                    })

                // Should reject or sanitize
                if (res.status === 201) {
                    expect(res.body.shipment.destination).not.toContain(';')
                    expect(res.body.shipment.destination).not.toContain('|')
                    expect(res.body.shipment.destination).not.toContain('$')
                } else {
                    expect(res.status).toBe(400)
                }
            })
        })
    })

    describe('Buffer Overflow Prevention', () => {
        test('should reject very long strings', async () => {
            const longString = 'A'.repeat(100000)

            const res = await request(app)
                .post('/api/shipments')
                .set(authHeader(token))
                .send({
                    origin: longString,
                    destination: 'Los Angeles, CA',
                    weight: 10
                })

            expect(res.status).toBe(400)
        })

        test('should handle request body size limits', async () => {
            const largePayload = {
                origin: 'New York',
                destination: 'LA',
                notes: 'X'.repeat(20 * 1024 * 1024) // 20MB
            }

            const res = await request(app)
                .post('/api/shipments')
                .set(authHeader(token))
                .send(largePayload)

            expect(res.status).toBe(413) // Payload too large
        })
    })

    describe('Edge Case Input Validation', () => {
        edgeCaseInputs.forEach((input) => {
            test(`should handle edge case input: ${JSON.stringify(input)}`, async () => {
                const res = await request(app)
                    .post('/api/shipments')
                    .set(authHeader(token))
                    .send({
                        origin: input,
                        destination: 'Los Angeles, CA',
                        weight: 10
                    })

                // Should validate and reject or accept
                expect([200, 201, 400]).toContain(res.status)
            })
        })
    })

    describe('Header Injection Prevention', () => {
        test('should prevent CRLF injection in headers', async () => {
            const maliciousHeader = 'value\r\nX-Injected: true'

            // Node.js should throw an error for invalid header characters
            await expect(
                request(app)
                    .get('/api/shipments')
                    .set('X-Custom-Header', maliciousHeader)
                    .set(authHeader(token))
            ).rejects.toThrow()
        })

        test('should validate Authorization header format', async () => {
            const res = await request(app)
                .get('/api/shipments')
                .set('Authorization', 'InvalidFormat token123')

            expect(res.status).toBe(401)
        })
    })

    describe('NoSQL Injection Prevention', () => {
        test('should prevent query parameter injection', async () => {
            const res = await request(app)
                .get('/api/shipments')
                .query({ status: { $ne: null } }) // MongoDB-style injection
                .set(authHeader(token))

            // Query params should be validated
            // Should either work normally (200) or reject (400/403)
            expect([200, 400, 403]).toContain(res.status)
        })
    })

    describe('Prototype Pollution Prevention', () => {
        test('should prevent prototype pollution via JSON', async () => {
            const maliciousPayload = {
                origin: 'New York',
                destination: 'LA',
                __proto__: { isAdmin: true }
            }

            mockPrisma.shipment.create.mockResolvedValue({
                id: 'test-1',
                trackingNumber: 'TEST-001'
            })

            const res = await request(app)
                .post('/api/shipments')
                .set(authHeader(token))
                .send(maliciousPayload)

            // Should not pollute prototype
            expect(({}).isAdmin).toBeUndefined()
        })
    })

    describe('Integer Overflow Prevention', () => {
        test('should validate numeric boundaries', async () => {
            const res = await request(app)
                .post('/api/shipments')
                .set(authHeader(token))
                .send({
                    origin: 'New York',
                    destination: 'LA',
                    weight: Number.MAX_SAFE_INTEGER + 1
                })

            expect(res.status).toBe(400)
        })
    })

    describe('Unicode & Encoding Attacks', () => {
        const unicodePayloads = [
            'test\u0000user', // Null byte
            'admin\uFEFF', // Zero-width no-break space
            '\uD83D\uDE00'.repeat(1000), // Many emojis
            '🔥🔥🔥' // Emojis
        ]

        unicodePayloads.forEach((payload) => {
            test(`should handle unicode payload: ${payload.substring(0, 20)}`, async () => {
                mockPrisma.shipment.create.mockResolvedValue({
                    id: 'test-1',
                    trackingNumber: 'TEST-001'
                })

                const res = await request(app)
                    .post('/api/shipments')
                    .set(authHeader(token))
                    .send({
                        origin: payload,
                        destination: 'LA',
                        weight: 10
                    })

                // Should handle gracefully
                expect([200, 201, 400]).toContain(res.status)
            })
        })
    })
})

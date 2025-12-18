/**
 * Integration tests for complete shipment lifecycle
 */
const request = require('supertest')
const { makeToken, authHeader } = require('../helpers/auth')
const { createUser } = require('../helpers/fixtures')

// Import the mocked Prisma from jest.setup.js
// The global jest.setup.js already mocks @prisma/client and ./src/db/prisma
// with proper transaction support


describe.skip('Shipment Lifecycle Integration', () => {
    let app
    let testUser
    let testShipment

    beforeAll(() => {
        process.env.NODE_ENV = 'test'
        process.env.JWT_SECRET = 'test-secret'
        process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test'

        // Clear module cache to get fresh app instance
        jest.resetModules()
        app = require('../../src/server')
    })

    beforeEach(() => {
        jest.clearAllMocks()

        testUser = createUser({
            id: 'user-1',
            email: 'test@example.com',
            role: 'user'
        })

        testShipment = {
            id: 'shipment-1',
            trackingNumber: 'TEST-001',
            origin: 'New York, NY',
            destination: 'Los Angeles, CA',
            status: 'PENDING',
            weight: 25.5,
            userId: testUser.id,
            driverId: null,
            createdAt: new Date(),
            updatedAt: new Date()
        }

        // Setup default mocks
        mockPrisma.user.findUnique.mockResolvedValue(testUser)
    })

    describe('Complete Workflow: Create → Update → Track → Deliver', () => {
        test('should complete full shipment lifecycle', async () => {
            const token = makeToken(['shipments:read', 'shipments:write'])

            // Step 1: Create shipment
            mockPrisma.shipment.create.mockResolvedValue(testShipment)

            const createRes = await request(app)
                .post('/api/shipments')
                .set(authHeader(token))
                .send({
                    origin: 'New York, NY',
                    destination: 'Los Angeles, CA',
                    weight: 25.5
                })

            expect(createRes.status).toBe(201)
            expect(createRes.body.ok).toBe(true)
            expect(createRes.body.shipment.trackingNumber).toBeDefined()

            const shipmentId = createRes.body.shipment.id

            // Step 2: Assign driver
            const assignedShipment = {
                ...testShipment,
                driverId: 'driver-1',
                status: 'ASSIGNED'
            }
            mockPrisma.shipment.findUnique.mockResolvedValue(assignedShipment)
            mockPrisma.shipment.update.mockResolvedValue(assignedShipment)

            const assignRes = await request(app)
                .patch(`/api/shipments/${shipmentId}`)
                .set(authHeader(token))
                .send({ driverId: 'driver-1' })

            expect(assignRes.status).toBe(200)
            expect(assignRes.body.shipment.driverId).toBe('driver-1')

            // Step 3: Update to in-transit
            const transitShipment = {
                ...assignedShipment,
                status: 'IN_TRANSIT'
            }
            mockPrisma.shipment.findUnique.mockResolvedValue(transitShipment)
            mockPrisma.shipment.update.mockResolvedValue(transitShipment)

            const transitRes = await request(app)
                .patch(`/api/shipments/${shipmentId}`)
                .set(authHeader(token))
                .send({ status: 'IN_TRANSIT' })

            expect(transitRes.status).toBe(200)
            expect(transitRes.body.shipment.status).toBe('IN_TRANSIT')

            // Step 4: Track shipment
            mockPrisma.shipment.findUnique.mockResolvedValue(transitShipment)

            const trackRes = await request(app)
                .get(`/api/shipments/${shipmentId}`)
                .set(authHeader(token))

            expect(trackRes.status).toBe(200)
            expect(trackRes.body.shipment.status).toBe('IN_TRANSIT')

            // Step 5: Mark as delivered
            const deliveredShipment = {
                ...transitShipment,
                status: 'DELIVERED'
            }
            mockPrisma.shipment.findUnique.mockResolvedValue(deliveredShipment)
            mockPrisma.shipment.update.mockResolvedValue(deliveredShipment)

            const deliverRes = await request(app)
                .patch(`/api/shipments/${shipmentId}`)
                .set(authHeader(token))
                .send({ status: 'DELIVERED' })

            expect(deliverRes.status).toBe(200)
            expect(deliverRes.body.shipment.status).toBe('DELIVERED')

            // Step 6: Verify final state
            mockPrisma.shipment.findUnique.mockResolvedValue(deliveredShipment)

            const finalRes = await request(app)
                .get(`/api/shipments/${shipmentId}`)
                .set(authHeader(token))

            expect(finalRes.status).toBe(200)
            expect(finalRes.body.shipment.status).toBe('DELIVERED')
        })

        test('should handle errors gracefully during lifecycle', async () => {
            const token = makeToken(['shipments:read', 'shipments:write'])

            // Create shipment
            mockPrisma.shipment.create.mockResolvedValue(testShipment)

            const createRes = await request(app)
                .post('/api/shipments')
                .set(authHeader(token))
                .send({
                    origin: 'New York, NY',
                    destination: 'Los Angeles, CA',
                    weight: 25.5
                })

            const shipmentId = createRes.body.shipment.id

            // Attempt invalid status transition
            mockPrisma.shipment.findUnique.mockResolvedValue(testShipment)

            const invalidRes = await request(app)
                .patch(`/api/shipments/${shipmentId}`)
                .set(authHeader(token))
                .send({ status: 'INVALID_STATUS' })

            expect(invalidRes.status).toBe(400)

            // Verify shipment unchanged
            mockPrisma.shipment.findUnique.mockResolvedValue(testShipment)

            const verifyRes = await request(app)
                .get(`/api/shipments/${shipmentId}`)
                .set(authHeader(token))

            expect(verifyRes.body.shipment.status).toBe('PENDING')
        })
    })

    describe('Multi-Shipment Operations', () => {
        test('should handle bulk shipment creation', async () => {
            const token = makeToken(['shipments:write'])

            const shipments = [
                {
                    origin: 'New York, NY',
                    destination: 'Boston, MA',
                    weight: 10
                },
                {
                    origin: 'Chicago, IL',
                    destination: 'Detroit, MI',
                    weight: 15
                },
                {
                    origin: 'LA, CA',
                    destination: 'San Diego, CA',
                    weight: 20
                }
            ]

            mockPrisma.shipment.create
                .mockResolvedValueOnce({ ...testShipment, id: 's-1' })
                .mockResolvedValueOnce({ ...testShipment, id: 's-2' })
                .mockResolvedValueOnce({ ...testShipment, id: 's-3' })

            const results = await Promise.all(
                shipments.map((s) =>
                    request(app)
                        .post('/api/shipments')
                        .set(authHeader(token))
                        .send(s)
                )
            )

            expect(results.every((r) => r.status === 201)).toBe(true)
            expect(mockPrisma.shipment.create).toHaveBeenCalledTimes(3)
        })

        test('should list shipments with pagination', async () => {
            const token = makeToken(['shipments:read'])

            mockPrisma.shipment.findMany.mockResolvedValue([
                testShipment,
                { ...testShipment, id: 'shipment-2' }
            ])

            const listRes = await request(app)
                .get('/api/shipments?page=1&limit=10')
                .set(authHeader(token))

            expect(listRes.status).toBe(200)
            expect(Array.isArray(listRes.body.shipments)).toBe(true)
        })
    })

    describe('Authentication & Authorization', () => {
        test('should require valid authentication', async () => {
            const res = await request(app)
                .get('/api/shipments')
                .set('Authorization', 'Bearer invalid-token')

            expect(res.status).toBe(401)
        })

        test('should require appropriate scopes', async () => {
            const token = makeToken(['read']) // Missing shipments:read

            const res = await request(app)
                .get('/api/shipments')
                .set(authHeader(token))

            expect(res.status).toBe(403)
        })

        test('should allow admin access to all shipments', async () => {
            const token = makeToken(['admin:all'])

            mockPrisma.shipment.findMany.mockResolvedValue([testShipment])

            const res = await request(app)
                .get('/api/shipments')
                .set(authHeader(token))

            expect(res.status).toBe(200)
        })
    })

    describe('Error Recovery', () => {
        test('should handle database connection errors', async () => {
            const token = makeToken(['shipments:read'])

            mockPrisma.shipment.findMany.mockRejectedValue(
                new Error('Database connection failed')
            )

            const res = await request(app)
                .get('/api/shipments')
                .set(authHeader(token))

            expect(res.status).toBe(500)
        })

        test('should handle concurrent updates gracefully', async () => {
            const token = makeToken(['shipments:write'])

            mockPrisma.shipment.findUnique.mockResolvedValue(testShipment)
            mockPrisma.shipment.update
                .mockResolvedValueOnce({ ...testShipment, status: 'IN_TRANSIT' })
                .mockRejectedValueOnce(new Error('Record version mismatch'))

            // First update succeeds
            const res1 = await request(app)
                .patch(`/api/shipments/${testShipment.id}`)
                .set(authHeader(token))
                .send({ status: 'IN_TRANSIT' })

            expect(res1.status).toBe(200)

            // Second concurrent update fails
            const res2 = await request(app)
                .patch(`/api/shipments/${testShipment.id}`)
                .set(authHeader(token))
                .send({ status: 'DELIVERED' })

            expect(res2.status).toBe(500)
        })
    })
})

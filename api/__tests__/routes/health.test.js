const request = require('supertest');
const express = require('express');
const healthRoutes = require('../../src/routes/health');

// Mock dependencies
jest.mock('../../package.json', () => ({ version: '2.0.0' }));
jest.mock('../../src/db/prisma', () => ({
    prisma: {
        $queryRaw: jest.fn()
    }
}));
jest.mock('../../src/services/cache', () => ({
    getStats: jest.fn()
}));
jest.mock('../../src/services/websocket', () => ({
    getConnectedClientsCount: jest.fn()
}));

const { prisma } = require('../../src/db/prisma');
const { getStats } = require('../../src/services/cache');
const { getConnectedClientsCount } = require('../../src/services/websocket');

describe('Health Routes', () => {
    let app;

    beforeEach(() => {
        app = express();
        app.use('/api', healthRoutes);
        jest.clearAllMocks();
    });

    describe('GET /health', () => {
        it('should return basic health check', async () => {
            const response = await request(app).get('/api/health');

            expect(response.status).toBe(200);
            expect(response.body).toMatchObject({
                status: 'ok',
                service: 'infamous-freight-api',
                version: '2.0.0',
                environment: 'test'
            });
            expect(response.body).toHaveProperty('timestamp');
            expect(response.body).toHaveProperty('uptime');
        });

        it('should include uptime in response', async () => {
            const response = await request(app).get('/api/health');

            expect(response.body.uptime).toBeGreaterThan(0);
            expect(typeof response.body.uptime).toBe('number');
        });

        it('should include ISO timestamp', async () => {
            const response = await request(app).get('/api/health');

            const timestamp = new Date(response.body.timestamp);
            expect(timestamp.toISOString()).toBe(response.body.timestamp);
        });
    });

    describe('GET /health/detailed', () => {
        it('should return detailed health with all services healthy', async () => {
            prisma.$queryRaw.mockResolvedValue([{ result: 1 }]);
            getStats.mockResolvedValue({ type: 'memory', hits: 100, misses: 10 });
            getConnectedClientsCount.mockReturnValue(5);

            const response = await request(app).get('/api/health/detailed');

            expect(response.status).toBe(200);
            expect(response.body).toMatchObject({
                status: 'healthy',
                service: 'infamous-freight-api',
                version: '2.0.0'
            });
            expect(response.body.checks.database.status).toBe('healthy');
            expect(response.body.checks.cache.status).toBe('healthy');
            expect(response.body.checks.websocket.status).toBe('healthy');
        });

        it('should return degraded status when database fails', async () => {
            prisma.$queryRaw.mockRejectedValue(new Error('Connection failed'));
            getStats.mockResolvedValue({ type: 'memory' });
            getConnectedClientsCount.mockReturnValue(0);

            const response = await request(app).get('/api/health/detailed');

            expect(response.status).toBe(503);
            expect(response.body.status).toBe('unhealthy');
            expect(response.body.checks.database.status).toBe('unhealthy');
            expect(response.body.checks.database.message).toContain('Database error');
        });

        it('should return healthy with degraded cache', async () => {
            prisma.$queryRaw.mockResolvedValue([{ result: 1 }]);
            getStats.mockRejectedValue(new Error('Cache error'));
            getConnectedClientsCount.mockReturnValue(3);

            const response = await request(app).get('/api/health/detailed');

            expect(response.status).toBe(200);
            expect(response.body.status).toBe('degraded');
            expect(response.body.checks.cache.status).toBe('degraded');
        });

        it('should return healthy with degraded websocket', async () => {
            prisma.$queryRaw.mockResolvedValue([{ result: 1 }]);
            getStats.mockResolvedValue({ type: 'memory' });
            getConnectedClientsCount.mockImplementation(() => {
                throw new Error('WebSocket error');
            });

            const response = await request(app).get('/api/health/detailed');

            expect(response.status).toBe(200);
            expect(response.body.status).toBe('degraded');
            expect(response.body.checks.websocket.status).toBe('degraded');
        });

        it('should include cache stats when available', async () => {
            prisma.$queryRaw.mockResolvedValue([{ result: 1 }]);
            const cacheStats = { type: 'redis', hits: 1000, misses: 50 };
            getStats.mockResolvedValue(cacheStats);
            getConnectedClientsCount.mockReturnValue(10);

            const response = await request(app).get('/api/health/detailed');

            expect(response.body.checks.cache.stats).toEqual(cacheStats);
        });

        it('should include connected clients count', async () => {
            prisma.$queryRaw.mockResolvedValue([{ result: 1 }]);
            getStats.mockResolvedValue({ type: 'memory' });
            getConnectedClientsCount.mockReturnValue(15);

            const response = await request(app).get('/api/health/detailed');

            expect(response.body.checks.websocket.connectedClients).toBe(15);
            expect(response.body.checks.websocket.message).toContain('15 clients');
        });
    });

    describe('GET /health/ready', () => {
        it('should return ready when database is connected', async () => {
            prisma.$queryRaw.mockResolvedValue([{ result: 1 }]);

            const response = await request(app).get('/api/health/ready');

            expect(response.status).toBe(200);
            expect(response.body).toEqual({ status: 'ready' });
        });

        it('should return not ready when database fails', async () => {
            prisma.$queryRaw.mockRejectedValue(new Error('Connection timeout'));

            const response = await request(app).get('/api/health/ready');

            expect(response.status).toBe(503);
            expect(response.body).toMatchObject({
                status: 'not ready',
                error: 'Connection timeout'
            });
        });

        it('should execute database query', async () => {
            prisma.$queryRaw.mockResolvedValue([{ result: 1 }]);

            await request(app).get('/api/health/ready');

            expect(prisma.$queryRaw).toHaveBeenCalledWith(
                expect.arrayContaining([expect.stringContaining('SELECT 1')])
            );
        });
    });

    describe('GET /health/live', () => {
        it('should always return alive', async () => {
            const response = await request(app).get('/api/health/live');

            expect(response.status).toBe(200);
            expect(response.body).toEqual({ status: 'alive' });
        });

        it('should not depend on external services', async () => {
            // Don't mock anything - liveness should always work
            const response = await request(app).get('/api/health/live');

            expect(response.status).toBe(200);
        });
    });

    describe('Environment information', () => {
        it('should include correct environment', async () => {
            const response = await request(app).get('/api/health');

            expect(response.body.environment).toBe('test');
        });

        it('should include service name', async () => {
            const response = await request(app).get('/api/health');

            expect(response.body.service).toBe('infamous-freight-api');
        });

        it('should include version from package.json', async () => {
            const response = await request(app).get('/api/health');

            expect(response.body.version).toBe('2.0.0');
        });
    });
});

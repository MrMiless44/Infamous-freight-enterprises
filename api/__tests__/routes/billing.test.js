const request = require('supertest');
const express = require('express');
const jwt = require('jsonwebtoken');
const billingRoutes = require('../../src/routes/billing');

describe('Billing Routes', () => {
    let app;
    let validToken;

    beforeEach(() => {
        app = express();
        app.use(express.json());
        app.use('/api', billingRoutes);

        const payload = {
            sub: 'user123',
            scopes: ['billing:read', 'billing:write']
        };
        validToken = jwt.sign(payload, process.env.JWT_SECRET);
    });

    describe('POST /api/billing/create-subscription', () => {
        it('should require authentication', async () => {
            const response = await request(app)
                .post('/api/billing/create-subscription')
                .send({ tier: 'premium', email: 'test@example.com' });

            expect(response.status).toBe(401);
        });

        it('should require billing:write scope', async () => {
            const token = jwt.sign({
                sub: 'user123',
                scopes: ['billing:read']
            }, process.env.JWT_SECRET);

            const response = await request(app)
                .post('/api/billing/create-subscription')
                .set('Authorization', `Bearer ${token}`)
                .send({ tier: 'premium', email: 'test@example.com' });

            expect(response.status).toBe(403);
        });

        it('should validate tier field', async () => {
            const response = await request(app)
                .post('/api/billing/create-subscription')
                .set('Authorization', `Bearer ${validToken}`)
                .send({ tier: '', email: 'test@example.com' });

            expect(response.status).toBe(400);
        });

        it('should validate email format', async () => {
            const response = await request(app)
                .post('/api/billing/create-subscription')
                .set('Authorization', `Bearer ${validToken}`)
                .send({ tier: 'premium', email: 'invalid-email' });

            expect(response.status).toBe(400);
        });

        it('should create subscription with valid data', async () => {
            const response = await request(app)
                .post('/api/billing/create-subscription')
                .set('Authorization', `Bearer ${validToken}`)
                .send({ tier: 'premium', email: 'test@example.com' });

            expect(response.status).toBe(201);
            expect(response.body).toMatchObject({
                ok: true,
                subscription: expect.objectContaining({
                    id: expect.stringContaining('sub_'),
                    tier: 'premium',
                    email: 'test@example.com',
                    status: 'active'
                })
            });
        });
    });

    describe('GET /api/billing/subscriptions', () => {
        it('should require authentication', async () => {
            const response = await request(app).get('/api/billing/subscriptions');

            expect(response.status).toBe(401);
        });

        it('should require billing:read scope', async () => {
            const token = jwt.sign({
                sub: 'user123',
                scopes: ['billing:write']
            }, process.env.JWT_SECRET);

            const response = await request(app)
                .get('/api/billing/subscriptions')
                .set('Authorization', `Bearer ${token}`);

            expect(response.status).toBe(403);
        });

        it('should return empty subscriptions list', async () => {
            const response = await request(app)
                .get('/api/billing/subscriptions')
                .set('Authorization', `Bearer ${validToken}`);

            expect(response.status).toBe(200);
            expect(response.body).toMatchObject({
                ok: true,
                subscriptions: [],
                count: 0
            });
        });
    });

    describe('POST /api/billing/cancel-subscription/:id', () => {
        it('should require authentication', async () => {
            const response = await request(app)
                .post('/api/billing/cancel-subscription/sub_123');

            expect(response.status).toBe(401);
        });

        it('should require billing:write scope', async () => {
            const token = jwt.sign({
                sub: 'user123',
                scopes: ['billing:read']
            }, process.env.JWT_SECRET);

            const response = await request(app)
                .post('/api/billing/cancel-subscription/sub_123')
                .set('Authorization', `Bearer ${token}`);

            expect(response.status).toBe(403);
        });

        it('should cancel subscription', async () => {
            const response = await request(app)
                .post('/api/billing/cancel-subscription/sub_123')
                .set('Authorization', `Bearer ${validToken}`);

            expect(response.status).toBe(200);
            expect(response.body).toMatchObject({
                ok: true,
                message: 'Subscription cancelled',
                id: 'sub_123'
            });
        });
    });
});

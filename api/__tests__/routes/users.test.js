const request = require('supertest');
const express = require('express');
const jwt = require('jsonwebtoken');
const usersRoutes = require('../../src/routes/users');

describe('Users Routes', () => {
    let app;
    let validToken;

    beforeEach(() => {
        app = express();
        app.use(express.json());
        app.use('/api', usersRoutes);

        const payload = {
            sub: 'user123',
            email: 'test@example.com',
            role: 'user',
            scopes: ['users:read', 'users:write']
        };
        validToken = jwt.sign(payload, process.env.JWT_SECRET);
    });

    describe('GET /api/users/me', () => {
        it('should require authentication', async () => {
            const response = await request(app).get('/api/users/me');

            expect(response.status).toBe(401);
        });

        it('should require users:read scope', async () => {
            const token = jwt.sign({
                sub: 'user123',
                scopes: ['other:scope']
            }, process.env.JWT_SECRET);

            const response = await request(app)
                .get('/api/users/me')
                .set('Authorization', `Bearer ${token}`);

            expect(response.status).toBe(403);
        });

        it('should return current user profile', async () => {
            const response = await request(app)
                .get('/api/users/me')
                .set('Authorization', `Bearer ${validToken}`);

            expect(response.status).toBe(200);
            expect(response.body).toMatchObject({
                ok: true,
                user: {
                    id: 'user123',
                    email: 'test@example.com',
                    role: 'user',
                    scopes: ['users:read', 'users:write']
                }
            });
        });
    });

    describe('PATCH /api/users/me', () => {
        it('should require authentication', async () => {
            const response = await request(app)
                .patch('/api/users/me')
                .send({ name: 'New Name' });

            expect(response.status).toBe(401);
        });

        it('should require users:write scope', async () => {
            const token = jwt.sign({
                sub: 'user123',
                scopes: ['users:read']
            }, process.env.JWT_SECRET);

            const response = await request(app)
                .patch('/api/users/me')
                .set('Authorization', `Bearer ${token}`)
                .send({ name: 'New Name' });

            expect(response.status).toBe(403);
        });

        it('should validate name max length', async () => {
            const response = await request(app)
                .patch('/api/users/me')
                .set('Authorization', `Bearer ${validToken}`)
                .send({ name: 'a'.repeat(101) });

            expect(response.status).toBe(400);
        });

        it('should validate email format', async () => {
            const response = await request(app)
                .patch('/api/users/me')
                .set('Authorization', `Bearer ${validToken}`)
                .send({ email: 'invalid-email' });

            expect(response.status).toBe(400);
        });

        it('should update user profile with valid data', async () => {
            const response = await request(app)
                .patch('/api/users/me')
                .set('Authorization', `Bearer ${validToken}`)
                .send({ name: 'John Doe', email: 'john@example.com' });

            expect(response.status).toBe(200);
            expect(response.body).toMatchObject({
                ok: true,
                user: {
                    id: 'user123',
                    name: 'John Doe',
                    email: 'john@example.com'
                }
            });
        });

        it('should accept partial updates', async () => {
            const response = await request(app)
                .patch('/api/users/me')
                .set('Authorization', `Bearer ${validToken}`)
                .send({ name: 'John Only' });

            expect(response.status).toBe(200);
            expect(response.body.user.name).toBe('John Only');
        });
    });

    describe('GET /api/users', () => {
        it('should require authentication', async () => {
            const response = await request(app).get('/api/users');

            expect(response.status).toBe(401);
        });

        it('should require admin scope', async () => {
            const token = jwt.sign({
                sub: 'user123',
                scopes: ['users:read', 'users:write']
            }, process.env.JWT_SECRET);

            const response = await request(app)
                .get('/api/users')
                .set('Authorization', `Bearer ${token}`);

            expect(response.status).toBe(403);
        });

        it('should list users for admin', async () => {
            const adminToken = jwt.sign({
                sub: 'admin123',
                scopes: ['admin']
            }, process.env.JWT_SECRET);

            const response = await request(app)
                .get('/api/users')
                .set('Authorization', `Bearer ${adminToken}`);

            expect(response.status).toBe(200);
            expect(response.body).toMatchObject({
                ok: true,
                users: [],
                count: 0
            });
        });
    });
});

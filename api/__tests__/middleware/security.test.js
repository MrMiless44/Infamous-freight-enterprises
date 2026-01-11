const request = require('supertest');
const express = require('express');
const jwt = require('jsonwebtoken');
const {
    limiters,
    authenticate,
    requireScope,
    auditLog
} = require('../../src/middleware/security');

describe('Security Middleware', () => {
    let app;

    beforeEach(() => {
        app = express();
        app.use(express.json());
    });

    describe('Rate Limiters', () => {
        it('should have general limiter configured', () => {
            expect(limiters.general).toBeDefined();
            expect(typeof limiters.general).toBe('function');
        });

        it('should have auth limiter configured', () => {
            expect(limiters.auth).toBeDefined();
            expect(typeof limiters.auth).toBe('function');
        });

        it('should have ai limiter configured', () => {
            expect(limiters.ai).toBeDefined();
            expect(typeof limiters.ai).toBe('function');
        });

        it('should have billing limiter configured', () => {
            expect(limiters.billing).toBeDefined();
            expect(typeof limiters.billing).toBe('function');
        });

        it('should apply rate limiting to routes', async () => {
            app.get('/test', limiters.general, (req, res) => {
                res.json({ ok: true });
            });

            const response = await request(app).get('/test');
            expect(response.status).toBe(200);
            expect(response.headers).toHaveProperty('x-ratelimit-limit');
        });
    });

    describe('authenticate middleware', () => {
        it('should return 401 when no authorization header', async () => {
            app.get('/protected', authenticate, (req, res) => {
                res.json({ ok: true });
            });

            const response = await request(app).get('/protected');
            expect(response.status).toBe(401);
            expect(response.body).toHaveProperty('error');
            expect(response.body.error).toContain('bearer token');
        });

        it('should return 401 when authorization header does not start with Bearer', async () => {
            app.get('/protected', authenticate, (req, res) => {
                res.json({ ok: true });
            });

            const response = await request(app)
                .get('/protected')
                .set('Authorization', 'Token invalid');

            expect(response.status).toBe(401);
            expect(response.body.error).toContain('bearer token');
        });

        it('should return 401 when token is invalid', async () => {
            app.get('/protected', authenticate, (req, res) => {
                res.json({ ok: true });
            });

            const response = await request(app)
                .get('/protected')
                .set('Authorization', 'Bearer invalid-token');

            expect(response.status).toBe(401);
            expect(response.body.error).toContain('Invalid or expired token');
        });

        it('should return 500 when JWT_SECRET is not configured', async () => {
            const originalSecret = process.env.JWT_SECRET;
            delete process.env.JWT_SECRET;

            app.get('/protected', authenticate, (req, res) => {
                res.json({ ok: true });
            });

            const token = jwt.sign({ sub: 'user123' }, 'any-secret');
            const response = await request(app)
                .get('/protected')
                .set('Authorization', `Bearer ${token}`);

            expect(response.status).toBe(500);
            expect(response.body.error).toContain('auth misconfiguration');

            process.env.JWT_SECRET = originalSecret;
        });

        it('should authenticate valid token and set req.user', async () => {
            app.get('/protected', authenticate, (req, res) => {
                res.json({ user: req.user });
            });

            const payload = {
                sub: 'user123',
                email: 'test@example.com',
                role: 'admin',
                scopes: ['read', 'write']
            };
            const token = jwt.sign(payload, process.env.JWT_SECRET);

            const response = await request(app)
                .get('/protected')
                .set('Authorization', `Bearer ${token}`);

            expect(response.status).toBe(200);
            expect(response.body.user).toMatchObject(payload);
        });

        it('should work with lowercase authorization header', async () => {
            app.get('/protected', authenticate, (req, res) => {
                res.json({ user: req.user });
            });

            const payload = { sub: 'user123' };
            const token = jwt.sign(payload, process.env.JWT_SECRET);

            const response = await request(app)
                .get('/protected')
                .set('authorization', `Bearer ${token}`);

            expect(response.status).toBe(200);
        });
    });

    describe('requireScope middleware', () => {
        beforeEach(() => {
            const payload = {
                sub: 'user123',
                scopes: ['read', 'write', 'admin']
            };
            const token = jwt.sign(payload, process.env.JWT_SECRET);

            app.use((req, res, next) => {
                req.headers.authorization = `Bearer ${token}`;
                next();
            });
            app.use(authenticate);
        });

        it('should allow access with required single scope', async () => {
            app.get('/test', requireScope('read'), (req, res) => {
                res.json({ ok: true });
            });

            const response = await request(app).get('/test');
            expect(response.status).toBe(200);
        });

        it('should allow access with required multiple scopes', async () => {
            app.get('/test', requireScope(['read', 'write']), (req, res) => {
                res.json({ ok: true });
            });

            const response = await request(app).get('/test');
            expect(response.status).toBe(200);
        });

        it('should deny access when scope is missing', async () => {
            app.get('/test', requireScope('delete'), (req, res) => {
                res.json({ ok: true });
            });

            const response = await request(app).get('/test');
            expect(response.status).toBe(403);
            expect(response.body.error).toContain('Insufficient scope');
            expect(response.body.required).toContain('delete');
        });

        it('should deny access when one of multiple scopes is missing', async () => {
            app.get('/test', requireScope(['read', 'delete']), (req, res) => {
                res.json({ ok: true });
            });

            const response = await request(app).get('/test');
            expect(response.status).toBe(403);
        });

        it('should handle missing user scopes array', async () => {
            app.use((req, res, next) => {
                req.user = { sub: 'user123' }; // No scopes array
                next();
            });

            app.get('/test', requireScope('read'), (req, res) => {
                res.json({ ok: true });
            });

            const response = await request(app).get('/test');
            expect(response.status).toBe(403);
        });
    });

    describe('auditLog middleware', () => {
        it('should log request information', async () => {
            const consoleSpy = jest.spyOn(console, 'info');

            app.get('/test', auditLog, (req, res) => {
                res.status(200).json({ ok: true });
            });

            await request(app).get('/test');

            expect(consoleSpy).toHaveBeenCalledWith(
                'request',
                expect.objectContaining({
                    method: 'GET',
                    status: 200,
                    duration: expect.any(Number),
                })
            );
        });

        it('should include user info when authenticated', async () => {
            const consoleSpy = jest.spyOn(console, 'info');
            const payload = { sub: 'user123' };
            const token = jwt.sign(payload, process.env.JWT_SECRET);

            app.get('/test', authenticate, auditLog, (req, res) => {
                res.json({ ok: true });
            });

            await request(app)
                .get('/test')
                .set('Authorization', `Bearer ${token}`);

            expect(consoleSpy).toHaveBeenCalledWith(
                'request',
                expect.objectContaining({
                    user: 'user123'
                })
            );
        });

        it('should mask authorization header', async () => {
            const consoleSpy = jest.spyOn(console, 'info');

            app.get('/test', auditLog, (req, res) => {
                res.json({ ok: true });
            });

            await request(app)
                .get('/test')
                .set('Authorization', 'Bearer secret-token');

            expect(consoleSpy).toHaveBeenCalledWith(
                'request',
                expect.objectContaining({
                    auth: '***'
                })
            );
        });

        it('should track request duration', async () => {
            const consoleSpy = jest.spyOn(console, 'info');

            app.get('/test', auditLog, async (req, res) => {
                await new Promise(resolve => setTimeout(resolve, 50));
                res.json({ ok: true });
            });

            await request(app).get('/test');

            expect(consoleSpy).toHaveBeenCalledWith(
                'request',
                expect.objectContaining({
                    duration: expect.any(Number)
                })
            );

            const logCall = consoleSpy.mock.calls[0][1];
            expect(logCall.duration).toBeGreaterThan(40);
        });
    });
});

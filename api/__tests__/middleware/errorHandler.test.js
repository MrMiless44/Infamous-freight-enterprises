const request = require('supertest');
const express = require('express');
const errorHandler = require('../../src/middleware/errorHandler');

describe('Error Handler Middleware', () => {
    let app;
    let consoleSpy;

    beforeEach(() => {
        app = express();
        app.use(express.json());
        consoleSpy = jest.spyOn(console, 'error').mockImplementation();
    });

    afterEach(() => {
        consoleSpy.mockRestore();
    });

    it('should handle errors with default 500 status', async () => {
        app.get('/test', (req, res, next) => {
            next(new Error('Test error'));
        });
        app.use(errorHandler);

        const response = await request(app).get('/test');

        expect(response.status).toBe(500);
        expect(response.body).toEqual({
            error: 'Test error'
        });
    });

    it('should handle errors with custom status code', async () => {
        app.get('/test', (req, res, next) => {
            const error = new Error('Not found');
            error.status = 404;
            next(error);
        });
        app.use(errorHandler);

        const response = await request(app).get('/test');

        expect(response.status).toBe(404);
        expect(response.body.error).toBe('Not found');
    });

    it('should handle errors with statusCode property', async () => {
        app.get('/test', (req, res, next) => {
            const error = new Error('Bad request');
            error.statusCode = 400;
            next(error);
        });
        app.use(errorHandler);

        const response = await request(app).get('/test');

        expect(response.status).toBe(400);
        expect(response.body.error).toBe('Bad request');
    });

    it('should log error details to console', async () => {
        app.get('/test', (req, res, next) => {
            const error = new Error('Test error');
            error.status = 500;
            next(error);
        });
        app.use(errorHandler);

        await request(app).get('/test');

        expect(consoleSpy).toHaveBeenCalledWith(
            'Request failed',
            expect.objectContaining({
                method: 'GET',
                path: '/test',
                status: 500,
                error: 'Test error'
            })
        );
    });

    it('should include user info in logs when available', async () => {
        app.get('/test', (req, res, next) => {
            req.user = { sub: 'user123' };
            next(new Error('Test error'));
        });
        app.use(errorHandler);

        await request(app).get('/test');

        expect(consoleSpy).toHaveBeenCalledWith(
            'Request failed',
            expect.objectContaining({
                user: 'user123'
            })
        );
    });

    it('should handle errors without message', async () => {
        app.get('/test', (req, res, next) => {
            const error = new Error();
            error.status = 500;
            next(error);
        });
        app.use(errorHandler);

        const response = await request(app).get('/test');

        expect(response.status).toBe(500);
        expect(response.body).toHaveProperty('error');
    });

    it('should include error stack in logs', async () => {
        app.get('/test', (req, res, next) => {
            const error = new Error('Test error');
            next(error);
        });
        app.use(errorHandler);

        await request(app).get('/test');

        expect(consoleSpy).toHaveBeenCalledWith(
            'Request failed',
            expect.objectContaining({
                stack: expect.any(String)
            })
        );
    });

    it('should handle errors in async routes', async () => {
        app.get('/test', async (req, res, next) => {
            try {
                throw new Error('Async error');
            } catch (err) {
                next(err);
            }
        });
        app.use(errorHandler);

        const response = await request(app).get('/test');

        expect(response.status).toBe(500);
        expect(response.body.error).toBe('Async error');
    });

    it('should prefer status over statusCode', async () => {
        app.get('/test', (req, res, next) => {
            const error = new Error('Conflict');
            error.status = 409;
            error.statusCode = 400;
            next(error);
        });
        app.use(errorHandler);

        const response = await request(app).get('/test');

        expect(response.status).toBe(409);
    });

    it('should work as final middleware in chain', async () => {
        let handlerCalled = false;

        app.get('/test', (req, res, next) => {
            next(new Error('Test'));
        });

        app.use((req, res, next) => {
            // This should not be called
            handlerCalled = true;
            next();
        });

        app.use(errorHandler);

        await request(app).get('/test');

        expect(handlerCalled).toBe(false);
    });

    it('should handle errors from multiple routes', async () => {
        app.get('/route1', (req, res, next) => {
            const err = new Error('Error 1');
            err.status = 400;
            next(err);
        });

        app.post('/route2', (req, res, next) => {
            const err = new Error('Error 2');
            err.status = 403;
            next(err);
        });

        app.use(errorHandler);

        const res1 = await request(app).get('/route1');
        expect(res1.status).toBe(400);
        expect(res1.body.error).toBe('Error 1');

        const res2 = await request(app).post('/route2');
        expect(res2.status).toBe(403);
        expect(res2.body.error).toBe('Error 2');
    });

    it('should handle JSON parse errors', async () => {
        app.post('/test', (req, res) => {
            res.json({ ok: true });
        });
        app.use(errorHandler);

        const response = await request(app)
            .post('/test')
            .set('Content-Type', 'application/json')
            .send('{"invalid json}');

        expect(response.status).toBeGreaterThanOrEqual(400);
    });
});

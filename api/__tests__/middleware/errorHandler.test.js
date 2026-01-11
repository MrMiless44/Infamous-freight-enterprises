const errorHandler = require('../../src/middleware/errorHandler');
const Sentry = require('@sentry/node');

describe('Error Handler Middleware', () => {
    let req, res, next;

    beforeEach(() => {
        req = {
            method: 'GET',
            path: '/test',
            user: null,
        };
        res = {
            status: jest.fn().mockReturnThis(),
            json: jest.fn().mockReturnThis(),
        };
        next = jest.fn();
        jest.clearAllMocks();
    });

    it('should handle error with default 500 status', () => {
        const error = new Error('Test error');

        errorHandler(error, req, res, next);

        expect(res.status).toHaveBeenCalledWith(500);
        expect(res.json).toHaveBeenCalledWith({
            error: 'Test error',
        });
    });

    it('should use error.status if provided', () => {
        const error = new Error('Not found');
        error.status = 404;

        errorHandler(error, req, res, next);

        expect(res.status).toHaveBeenCalledWith(404);
        expect(res.json).toHaveBeenCalledWith({
            error: 'Not found',
        });
    });

    it('should use error.statusCode if provided', () => {
        const error = new Error('Bad request');
        error.statusCode = 400;

        errorHandler(error, req, res, next);

        expect(res.status).toHaveBeenCalledWith(400);
    });

    it('should log error details', () => {
        const error = new Error('Test error');
        error.stack = 'Error stack trace';

        errorHandler(error, req, res, next);

        expect(console.error).toHaveBeenCalledWith(
            'Request failed',
            expect.objectContaining({
                method: 'GET',
                path: '/test',
                status: 500,
                error: 'Test error',
            })
        );
    });

    it('should include user info in logs when authenticated', () => {
        req.user = { sub: 'user-123' };
        const error = new Error('Test error');

        errorHandler(error, req, res, next);

        expect(console.error).toHaveBeenCalledWith(
            'Request failed',
            expect.objectContaining({
                user: 'user-123',
            })
        );
    });

    it('should capture exception with Sentry', () => {
        process.env.SENTRY_DSN = 'https://test@sentry.io/123';
        const error = new Error('Sentry test');

        errorHandler(error, req, res, next);

        expect(Sentry.captureException).toHaveBeenCalledWith(
            error,
            expect.objectContaining({
                tags: {
                    path: '/test',
                    method: 'GET',
                },
            })
        );

        delete process.env.SENTRY_DSN;
    });

    it('should include user in Sentry context when authenticated', () => {
        process.env.SENTRY_DSN = 'https://test@sentry.io/123';
        req.user = { sub: 'user-456' };
        const error = new Error('Sentry test');

        errorHandler(error, req, res, next);

        expect(Sentry.captureException).toHaveBeenCalledWith(
            error,
            expect.objectContaining({
                user: { id: 'user-456' },
            })
        );

        delete process.env.SENTRY_DSN;
    });

    it('should handle error without message', () => {
        const error = new Error();

        errorHandler(error, req, res, next);

        expect(res.json).toHaveBeenCalledWith({
            error: 'Internal Server Error',
        });
    });
});

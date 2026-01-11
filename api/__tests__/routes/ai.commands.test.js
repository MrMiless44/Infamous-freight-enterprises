const request = require('supertest');
const express = require('express');
const jwt = require('jsonwebtoken');
const aiRoutes = require('../../src/routes/ai.commands');

describe('AI Commands Routes', () => {
    let app;
    let validToken;

    beforeEach(() => {
        app = express();
        app.use(express.json());
        app.use('/api', aiRoutes);

        const payload = {
            sub: 'user123',
            scopes: ['ai:command', 'ai:history']
        };
        validToken = jwt.sign(payload, process.env.JWT_SECRET);
    });

    describe('POST /api/ai/command', () => {
        it('should require authentication', async () => {
            const response = await request(app)
                .post('/api/ai/command')
                .send({ command: 'test' });

            expect(response.status).toBe(401);
        });

        it('should require ai:command scope', async () => {
            const token = jwt.sign({
                sub: 'user123',
                scopes: ['other:scope']
            }, process.env.JWT_SECRET);

            const response = await request(app)
                .post('/api/ai/command')
                .set('Authorization', `Bearer ${token}`)
                .send({ command: 'test' });

            expect(response.status).toBe(403);
        });

        it('should validate command field is string', async () => {
            const response = await request(app)
                .post('/api/ai/command')
                .set('Authorization', `Bearer ${validToken}`)
                .send({ command: 12345 });

            expect(response.status).toBe(400);
        });

        it('should validate command field is not empty', async () => {
            const response = await request(app)
                .post('/api/ai/command')
                .set('Authorization', `Bearer ${validToken}`)
                .send({ command: '' });

            expect(response.status).toBe(400);
        });

        it('should enforce max length of 500 characters', async () => {
            const response = await request(app)
                .post('/api/ai/command')
                .set('Authorization', `Bearer ${validToken}`)
                .send({ command: 'a'.repeat(501) });

            expect(response.status).toBe(400);
        });

        it('should process valid AI command', async () => {
            const response = await request(app)
                .post('/api/ai/command')
                .set('Authorization', `Bearer ${validToken}`)
                .send({ command: 'test command' });

            expect(response.status).toBe(200);
            expect(response.body).toMatchObject({
                ok: true,
                command: 'test command',
                result: expect.any(String)
            });
        });

        it('should return timestamp in response', async () => {
            const response = await request(app)
                .post('/api/ai/command')
                .set('Authorization', `Bearer ${validToken}`)
                .send({ command: 'test' });

            expect(response.body.timestamp).toBeDefined();
            const timestamp = new Date(response.body.timestamp);
            expect(timestamp.toISOString()).toBe(response.body.timestamp);
        });
    });

    describe('GET /api/ai/history', () => {
        it('should require authentication', async () => {
            const response = await request(app).get('/api/ai/history');

            expect(response.status).toBe(401);
        });

        it('should require ai:history scope', async () => {
            const token = jwt.sign({
                sub: 'user123',
                scopes: ['ai:command'] // Has command but not history
            }, process.env.JWT_SECRET);

            const response = await request(app)
                .get('/api/ai/history')
                .set('Authorization', `Bearer ${token}`);

            expect(response.status).toBe(403);
        });

        it('should return empty history', async () => {
            const response = await request(app)
                .get('/api/ai/history')
                .set('Authorization', `Bearer ${validToken}`);

            expect(response.status).toBe(200);
            expect(response.body).toMatchObject({
                ok: true,
                history: [],
                count: 0
            });
        });
    });
});

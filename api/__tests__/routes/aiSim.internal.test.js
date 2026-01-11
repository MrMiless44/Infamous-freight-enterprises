const request = require('supertest');
const express = require('express');
const aiSimRoutes = require('../../src/routes/aiSim.internal');

describe('AI Sim Internal Routes', () => {
    let app;

    beforeEach(() => {
        app = express();
        app.use(express.json());
        app.use('/internal', aiSimRoutes);
    });

    describe('GET /internal/ai/simulate', () => {
        it('should return 400 when prompt is missing', async () => {
            const response = await request(app).get('/internal/ai/simulate');

            expect(response.status).toBe(400);
            expect(response.body).toMatchObject({
                ok: false,
                error: 'Prompt is required'
            });
        });

        it('should return synthetic AI response', async () => {
            const response = await request(app)
                .get('/internal/ai/simulate')
                .query({ prompt: 'test prompt' });

            expect(response.status).toBe(200);
            expect(response.body).toMatchObject({
                ok: true,
                prompt: 'test prompt',
                completion: expect.stringContaining('test prompt'),
                model: 'synthetic-v1'
            });
        });

        it('should include timestamp in response', async () => {
            const response = await request(app)
                .get('/internal/ai/simulate')
                .query({ prompt: 'test' });

            expect(response.body.timestamp).toBeDefined();
            const timestamp = new Date(response.body.timestamp);
            expect(timestamp.toISOString()).toBe(response.body.timestamp);
        });

        it('should not require authentication', async () => {
            const response = await request(app)
                .get('/internal/ai/simulate')
                .query({ prompt: 'test' });

            expect(response.status).toBe(200);
        });
    });

    describe('POST /internal/ai/batch', () => {
        it('should return 400 when prompts is not an array', async () => {
            const response = await request(app)
                .post('/internal/ai/batch')
                .send({ prompts: 'not-an-array' });

            expect(response.status).toBe(400);
            expect(response.body).toMatchObject({
                ok: false,
                error: 'Prompts must be an array'
            });
        });

        it('should process batch of prompts', async () => {
            const prompts = ['prompt1', 'prompt2', 'prompt3'];

            const response = await request(app)
                .post('/internal/ai/batch')
                .send({ prompts });

            expect(response.status).toBe(200);
            expect(response.body).toMatchObject({
                ok: true,
                count: 3
            });
            expect(response.body.results).toHaveLength(3);
        });

        it('should return results with correct indices', async () => {
            const prompts = ['a', 'b', 'c'];

            const response = await request(app)
                .post('/internal/ai/batch')
                .send({ prompts });

            expect(response.body.results[0]).toMatchObject({
                index: 0,
                prompt: 'a'
            });
            expect(response.body.results[1]).toMatchObject({
                index: 1,
                prompt: 'b'
            });
            expect(response.body.results[2]).toMatchObject({
                index: 2,
                prompt: 'c'
            });
        });

        it('should include model and completion for each result', async () => {
            const response = await request(app)
                .post('/internal/ai/batch')
                .send({ prompts: ['test'] });

            expect(response.body.results[0]).toMatchObject({
                prompt: 'test',
                completion: expect.any(String),
                model: 'synthetic-v1'
            });
        });

        it('should handle empty prompts array', async () => {
            const response = await request(app)
                .post('/internal/ai/batch')
                .send({ prompts: [] });

            expect(response.status).toBe(200);
            expect(response.body).toMatchObject({
                ok: true,
                results: [],
                count: 0
            });
        });
    });
});

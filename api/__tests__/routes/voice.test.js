const request = require('supertest');
const express = require('express');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
const voiceRoutes = require('../../src/routes/voice');

describe('Voice Routes', () => {
    let app;
    let validToken;

    beforeEach(() => {
        app = express();
        app.use(express.json());
        app.use('/api', voiceRoutes);

        const payload = {
            sub: 'user123',
            scopes: ['voice:ingest', 'voice:command']
        };
        validToken = jwt.sign(payload, process.env.JWT_SECRET);
    });

    describe('POST /api/voice/ingest', () => {
        it('should require authentication', async () => {
            const response = await request(app)
                .post('/api/voice/ingest');

            expect(response.status).toBe(401);
        });

        it('should require voice:ingest scope', async () => {
            const token = jwt.sign({
                sub: 'user123',
                scopes: ['voice:command']
            }, process.env.JWT_SECRET);

            const response = await request(app)
                .post('/api/voice/ingest')
                .set('Authorization', `Bearer ${token}`);

            expect(response.status).toBe(403);
        });

        it('should return 400 when no file uploaded', async () => {
            const response = await request(app)
                .post('/api/voice/ingest')
                .set('Authorization', `Bearer ${validToken}`);

            expect(response.status).toBe(400);
            expect(response.body).toMatchObject({
                ok: false,
                error: 'No audio file uploaded'
            });
        });

        it('should accept valid audio file', async () => {
            // Create a temporary test file
            const testBuffer = Buffer.from('fake audio data');

            const response = await request(app)
                .post('/api/voice/ingest')
                .set('Authorization', `Bearer ${validToken}`)
                .attach('audio', testBuffer, {
                    filename: 'test.mp3',
                    contentType: 'audio/mpeg'
                });

            expect(response.status).toBe(200);
            expect(response.body).toMatchObject({
                ok: true,
                file: expect.objectContaining({
                    originalName: 'test.mp3',
                    mimetype: 'audio/mpeg'
                })
            });
        });
    });

    describe('POST /api/voice/command', () => {
        it('should require authentication', async () => {
            const response = await request(app)
                .post('/api/voice/command')
                .send({ text: 'test' });

            expect(response.status).toBe(401);
        });

        it('should require voice:command scope', async () => {
            const token = jwt.sign({
                sub: 'user123',
                scopes: ['voice:ingest']
            }, process.env.JWT_SECRET);

            const response = await request(app)
                .post('/api/voice/command')
                .set('Authorization', `Bearer ${token}`)
                .send({ text: 'test' });

            expect(response.status).toBe(403);
        });

        it('should return 400 when text is missing', async () => {
            const response = await request(app)
                .post('/api/voice/command')
                .set('Authorization', `Bearer ${validToken}`)
                .send({});

            expect(response.status).toBe(400);
            expect(response.body).toMatchObject({
                ok: false,
                error: 'Text command is required'
            });
        });

        it('should process voice command with text', async () => {
            const response = await request(app)
                .post('/api/voice/command')
                .set('Authorization', `Bearer ${validToken}`)
                .send({ text: 'test command' });

            expect(response.status).toBe(200);
            expect(response.body).toMatchObject({
                ok: true,
                command: 'test command',
                result: expect.any(String)
            });
        });
    });
});

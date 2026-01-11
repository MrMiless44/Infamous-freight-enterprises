const request = require('supertest');
const express = require('express');
const {
    validateString,
    validateEmail,
    validatePhone,
    validateUUID,
    handleValidationErrors
} = require('../../src/middleware/validation');

describe('Validation Middleware', () => {
    let app;

    beforeEach(() => {
        app = express();
        app.use(express.json());
    });

    describe('validateString', () => {
        it('should pass validation for valid string', async () => {
            app.post('/test', [
                validateString('name'),
                handleValidationErrors
            ], (req, res) => {
                res.json({ ok: true });
            });

            const response = await request(app)
                .post('/test')
                .send({ name: 'John Doe' });

            expect(response.status).toBe(200);
        });

        it('should fail when field is not a string', async () => {
            app.post('/test', [
                validateString('name'),
                handleValidationErrors
            ], (req, res) => {
                res.json({ ok: true });
            });

            const response = await request(app)
                .post('/test')
                .send({ name: 12345 });

            expect(response.status).toBe(400);
            expect(response.body.error).toBe('Validation failed');
            expect(response.body.details).toEqual(
                expect.arrayContaining([
                    expect.objectContaining({
                        field: 'name',
                        msg: expect.stringContaining('must be a string')
                    })
                ])
            );
        });

        it('should fail when field is empty', async () => {
            app.post('/test', [
                validateString('name'),
                handleValidationErrors
            ], (req, res) => {
                res.json({ ok: true });
            });

            const response = await request(app)
                .post('/test')
                .send({ name: '' });

            expect(response.status).toBe(400);
            expect(response.body.details).toEqual(
                expect.arrayContaining([
                    expect.objectContaining({
                        msg: expect.stringContaining('must not be empty')
                    })
                ])
            );
        });

        it('should trim whitespace', async () => {
            let receivedValue;
            app.post('/test', [
                validateString('name'),
                handleValidationErrors
            ], (req, res) => {
                receivedValue = req.body.name;
                res.json({ ok: true });
            });

            await request(app)
                .post('/test')
                .send({ name: '  John Doe  ' });

            expect(receivedValue).toBe('John Doe');
        });

        it('should enforce custom maxLength', async () => {
            app.post('/test', [
                validateString('name', { maxLength: 5 }),
                handleValidationErrors
            ], (req, res) => {
                res.json({ ok: true });
            });

            const response = await request(app)
                .post('/test')
                .send({ name: 'Very Long Name' });

            expect(response.status).toBe(400);
            expect(response.body.details).toEqual(
                expect.arrayContaining([
                    expect.objectContaining({
                        msg: expect.stringContaining('too long')
                    })
                ])
            );
        });

        it('should enforce default maxLength of 1000', async () => {
            app.post('/test', [
                validateString('text'),
                handleValidationErrors
            ], (req, res) => {
                res.json({ ok: true });
            });

            const response = await request(app)
                .post('/test')
                .send({ text: 'a'.repeat(1001) });

            expect(response.status).toBe(400);
        });
    });

    describe('validateEmail', () => {
        it('should pass validation for valid email', async () => {
            app.post('/test', [
                validateEmail('email'),
                handleValidationErrors
            ], (req, res) => {
                res.json({ ok: true });
            });

            const response = await request(app)
                .post('/test')
                .send({ email: 'test@example.com' });

            expect(response.status).toBe(200);
        });

        it('should fail for invalid email format', async () => {
            app.post('/test', [
                validateEmail('email'),
                handleValidationErrors
            ], (req, res) => {
                res.json({ ok: true });
            });

            const response = await request(app)
                .post('/test')
                .send({ email: 'invalid-email' });

            expect(response.status).toBe(400);
            expect(response.body.details).toEqual(
                expect.arrayContaining([
                    expect.objectContaining({
                        field: 'email',
                        msg: 'Invalid email'
                    })
                ])
            );
        });

        it('should normalize email', async () => {
            let receivedEmail;
            app.post('/test', [
                validateEmail('email'),
                handleValidationErrors
            ], (req, res) => {
                receivedEmail = req.body.email;
                res.json({ ok: true });
            });

            await request(app)
                .post('/test')
                .send({ email: 'Test@EXAMPLE.COM' });

            expect(receivedEmail).toBe('test@example.com');
        });

        it('should support custom field name', async () => {
            app.post('/test', [
                validateEmail('userEmail'),
                handleValidationErrors
            ], (req, res) => {
                res.json({ ok: true });
            });

            const response = await request(app)
                .post('/test')
                .send({ userEmail: 'invalid' });

            expect(response.status).toBe(400);
            expect(response.body.details[0].field).toBe('userEmail');
        });
    });

    describe('validatePhone', () => {
        it('should pass validation for valid phone number', async () => {
            app.post('/test', [
                validatePhone('phone'),
                handleValidationErrors
            ], (req, res) => {
                res.json({ ok: true });
            });

            const response = await request(app)
                .post('/test')
                .send({ phone: '+14155552671' });

            expect(response.status).toBe(200);
        });

        it('should fail for invalid phone number', async () => {
            app.post('/test', [
                validatePhone('phone'),
                handleValidationErrors
            ], (req, res) => {
                res.json({ ok: true });
            });

            const response = await request(app)
                .post('/test')
                .send({ phone: 'not-a-phone' });

            expect(response.status).toBe(400);
            expect(response.body.details).toEqual(
                expect.arrayContaining([
                    expect.objectContaining({
                        field: 'phone',
                        msg: 'Invalid phone number'
                    })
                ])
            );
        });

        it('should support custom field name', async () => {
            app.post('/test', [
                validatePhone('contactNumber'),
                handleValidationErrors
            ], (req, res) => {
                res.json({ ok: true });
            });

            const response = await request(app)
                .post('/test')
                .send({ contactNumber: 'invalid' });

            expect(response.status).toBe(400);
            expect(response.body.details[0].field).toBe('contactNumber');
        });
    });

    describe('validateUUID', () => {
        it('should pass validation for valid UUID', async () => {
            app.get('/test/:id', [
                validateUUID('id'),
                handleValidationErrors
            ], (req, res) => {
                res.json({ ok: true });
            });

            const response = await request(app)
                .get('/test/550e8400-e29b-41d4-a716-446655440000');

            expect(response.status).toBe(200);
        });

        it('should fail for invalid UUID', async () => {
            app.get('/test/:id', [
                validateUUID('id'),
                handleValidationErrors
            ], (req, res) => {
                res.json({ ok: true });
            });

            const response = await request(app)
                .get('/test/invalid-uuid');

            expect(response.status).toBe(400);
            expect(response.body.details).toEqual(
                expect.arrayContaining([
                    expect.objectContaining({
                        field: 'id',
                        msg: 'Invalid UUID'
                    })
                ])
            );
        });

        it('should support custom field name', async () => {
            app.get('/test/:userId', [
                validateUUID('userId'),
                handleValidationErrors
            ], (req, res) => {
                res.json({ ok: true });
            });

            const response = await request(app)
                .get('/test/not-a-uuid');

            expect(response.status).toBe(400);
            expect(response.body.details[0].field).toBe('userId');
        });
    });

    describe('handleValidationErrors', () => {
        it('should pass when no validation errors', async () => {
            app.post('/test', [
                validateString('name'),
                handleValidationErrors
            ], (req, res) => {
                res.json({ ok: true });
            });

            const response = await request(app)
                .post('/test')
                .send({ name: 'John' });

            expect(response.status).toBe(200);
        });

        it('should return 400 with multiple validation errors', async () => {
            app.post('/test', [
                validateString('name'),
                validateEmail('email'),
                handleValidationErrors
            ], (req, res) => {
                res.json({ ok: true });
            });

            const response = await request(app)
                .post('/test')
                .send({ name: '', email: 'invalid' });

            expect(response.status).toBe(400);
            expect(response.body.error).toBe('Validation failed');
            expect(response.body.details).toHaveLength(2);
            expect(response.body.details).toEqual(
                expect.arrayContaining([
                    expect.objectContaining({ field: 'name' }),
                    expect.objectContaining({ field: 'email' })
                ])
            );
        });

        it('should return structured error response', async () => {
            app.post('/test', [
                validateString('field1'),
                handleValidationErrors
            ], (req, res) => {
                res.json({ ok: true });
            });

            const response = await request(app)
                .post('/test')
                .send({ field1: 123 });

            expect(response.body).toMatchObject({
                error: 'Validation failed',
                details: expect.arrayContaining([
                    expect.objectContaining({
                        field: expect.any(String),
                        msg: expect.any(String)
                    })
                ])
            });
        });
    });

    describe('Multiple validators combined', () => {
        it('should validate multiple fields successfully', async () => {
            app.post('/test', [
                validateString('name'),
                validateEmail('email'),
                validatePhone('phone'),
                handleValidationErrors
            ], (req, res) => {
                res.json({ ok: true });
            });

            const response = await request(app)
                .post('/test')
                .send({
                    name: 'John Doe',
                    email: 'john@example.com',
                    phone: '+14155552671'
                });

            expect(response.status).toBe(200);
        });

        it('should report all validation failures', async () => {
            app.post('/test', [
                validateString('name'),
                validateEmail('email'),
                validatePhone('phone'),
                handleValidationErrors
            ], (req, res) => {
                res.json({ ok: true });
            });

            const response = await request(app)
                .post('/test')
                .send({
                    name: '',
                    email: 'invalid',
                    phone: 'not-a-phone'
                });

            expect(response.status).toBe(400);
            expect(response.body.details).toHaveLength(3);
        });
    });
});

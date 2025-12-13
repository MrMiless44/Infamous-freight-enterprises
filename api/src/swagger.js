/**
 * @swagger
 * /api/health:
 *   get:
 *     summary: Health check endpoint
 *     tags: [Health]
 *     responses:
 *       200:
 *         description: API is healthy
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   example: "ok"
 *                 timestamp:
 *                   type: string
 *                   format: date-time
 *                 uptime:
 *                   type: number
 */

/**
 * @swagger
 * /api/billing:
 *   post:
 *     summary: Create billing record
 *     tags: [Billing]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [amount, currency]
 *             properties:
 *               amount:
 *                 type: number
 *               currency:
 *                 type: string
 *               description:
 *                 type: string
 *     responses:
 *       201:
 *         description: Billing record created
 *       400:
 *         description: Invalid input
 */

/**
 * @swagger
 * /api/voice:
 *   post:
 *     summary: Process voice command
 *     tags: [Voice]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [audio]
 *             properties:
 *               audio:
 *                 type: string
 *                 format: base64
 *     responses:
 *       200:
 *         description: Voice processed
 *       400:
 *         description: Invalid audio
 */

module.exports = {};

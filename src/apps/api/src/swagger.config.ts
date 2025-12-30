/**
 * Swagger/OpenAPI Configuration
 * API documentation setup
 */

import swaggerJsdoc from "swagger-jsdoc";

const swaggerOptions = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "Infamous Freight Enterprises API",
      version: "1.0.0",
      description: "RESTful API for freight logistics and shipment management",
      contact: {
        name: "Support",
        email: "support@infamousfreight.com",
        url: "https://infamousfreight.com",
      },
      license: {
        name: "MIT",
      },
    },
    servers: [
      {
        url: "http://localhost:4000",
        description: "Development server",
      },
      {
        url: "https://api.infamousfreight.com",
        description: "Production server",
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT",
        },
      },
      schemas: {
        User: {
          type: "object",
          properties: {
            id: { type: "string", format: "uuid" },
            email: { type: "string", format: "email" },
            name: { type: "string" },
            role: {
              type: "string",
              enum: ["ADMIN", "DISPATCHER", "DRIVER", "CUSTOMER"],
            },
            createdAt: { type: "string", format: "date-time" },
            updatedAt: { type: "string", format: "date-time" },
          },
          required: ["id", "email", "name", "role"],
        },
        Shipment: {
          type: "object",
          properties: {
            id: { type: "string", format: "uuid" },
            trackingNumber: { type: "string" },
            status: {
              type: "string",
              enum: [
                "PENDING",
                "ASSIGNED",
                "IN_TRANSIT",
                "DELIVERED",
                "CANCELLED",
              ],
            },
            customerId: { type: "string", format: "uuid" },
            driverId: { type: "string", format: "uuid" },
            originCity: { type: "string" },
            originState: { type: "string" },
            destinationCity: { type: "string" },
            destinationState: { type: "string" },
            weight: { type: "number" },
            rate: { type: "number", format: "float" },
            pickupDate: { type: "string", format: "date-time" },
            estimatedDelivery: { type: "string", format: "date-time" },
            actualDelivery: {
              type: "string",
              format: "date-time",
              nullable: true,
            },
            createdAt: { type: "string", format: "date-time" },
            updatedAt: { type: "string", format: "date-time" },
          },
          required: [
            "id",
            "trackingNumber",
            "status",
            "customerId",
            "originCity",
            "destinationCity",
            "weight",
          ],
        },
        Driver: {
          type: "object",
          properties: {
            id: { type: "string", format: "uuid" },
            userId: { type: "string", format: "uuid" },
            licenseNumber: { type: "string" },
            licenseExpiry: { type: "string", format: "date" },
            yearsExperience: { type: "integer" },
            status: {
              type: "string",
              enum: ["ACTIVE", "INACTIVE", "ON_LEAVE"],
            },
            currentLatitude: { type: "number", format: "float" },
            currentLongitude: { type: "number", format: "float" },
            createdAt: { type: "string", format: "date-time" },
            updatedAt: { type: "string", format: "date-time" },
          },
          required: ["id", "userId", "licenseNumber", "status"],
        },
        Invoice: {
          type: "object",
          properties: {
            id: { type: "string", format: "uuid" },
            invoiceNumber: { type: "string" },
            customerId: { type: "string", format: "uuid" },
            shipmentId: { type: "string", format: "uuid" },
            amount: { type: "number", format: "float" },
            taxAmount: { type: "number", format: "float" },
            totalAmount: { type: "number", format: "float" },
            status: {
              type: "string",
              enum: ["DRAFT", "SENT", "PAID", "OVERDUE"],
            },
            dueDate: { type: "string", format: "date" },
            issuedDate: { type: "string", format: "date" },
            createdAt: { type: "string", format: "date-time" },
            updatedAt: { type: "string", format: "date-time" },
          },
          required: [
            "id",
            "invoiceNumber",
            "customerId",
            "amount",
            "totalAmount",
            "status",
          ],
        },
        Error: {
          type: "object",
          properties: {
            error: { type: "string" },
            message: { type: "string" },
            statusCode: { type: "integer" },
            timestamp: { type: "string", format: "date-time" },
          },
          required: ["error", "message", "statusCode"],
        },
        ApiResponse: {
          type: "object",
          properties: {
            success: { type: "boolean" },
            data: { type: "object" },
            error: { type: "string" },
            timestamp: { type: "string", format: "date-time" },
          },
          required: ["success", "timestamp"],
        },
      },
    },
    security: [{ bearerAuth: [] }],
  },
  apis: ["./src/routes/*.ts", "./src/routes/*.js"],
};

export const swaggerSpec = swaggerJsdoc(swaggerOptions);

/**
 * @swagger
 * /api/health:
 *   get:
 *     summary: Health check endpoint
 *     description: Returns API health status
 *     tags:
 *       - Health
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
 *       503:
 *         description: API is degraded
 */

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: User login
 *     description: Authenticate user and get JWT token
 *     tags:
 *       - Authentication
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *                 format: password
 *             required:
 *               - email
 *               - password
 *     responses:
 *       200:
 *         description: Login successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                 user:
 *                   $ref: '#/components/schemas/User'
 *       401:
 *         description: Invalid credentials
 *       400:
 *         description: Validation error
 */

/**
 * @swagger
 * /api/shipments:
 *   get:
 *     summary: List all shipments
 *     description: Get paginated list of shipments with optional filters
 *     tags:
 *       - Shipments
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: status
 *         schema:
 *           type: string
 *           enum: [PENDING, ASSIGNED, IN_TRANSIT, DELIVERED, CANCELLED]
 *         description: Filter by shipment status
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           default: 1
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 20
 *     responses:
 *       200:
 *         description: Shipments retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 data:
 *                   type: array
 *                   items:
 *                     $ref: '#/components/schemas/Shipment'
 *                 total:
 *                   type: integer
 *                 page:
 *                   type: integer
 *       401:
 *         description: Unauthorized
 *   post:
 *     summary: Create new shipment
 *     description: Create a new shipment record
 *     tags:
 *       - Shipments
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/Shipment'
 *     responses:
 *       201:
 *         description: Shipment created successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Shipment'
 *       400:
 *         description: Validation error
 *       401:
 *         description: Unauthorized
 */

/**
 * @swagger
 * /api/shipments/{id}:
 *   get:
 *     summary: Get shipment by ID
 *     tags:
 *       - Shipments
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *     responses:
 *       200:
 *         description: Shipment found
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Shipment'
 *       404:
 *         description: Shipment not found
 *   patch:
 *     summary: Update shipment
 *     tags:
 *       - Shipments
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               status:
 *                 type: string
 *     responses:
 *       200:
 *         description: Shipment updated
 *       404:
 *         description: Shipment not found
 *   delete:
 *     summary: Delete shipment
 *     tags:
 *       - Shipments
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       204:
 *         description: Shipment deleted
 *       404:
 *         description: Shipment not found
 */

/**
 * @swagger
 * /api/invoices:
 *   get:
 *     summary: List invoices
 *     tags:
 *       - Invoices
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Invoices retrieved
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Invoice'
 *   post:
 *     summary: Create invoice
 *     tags:
 *       - Invoices
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/Invoice'
 *     responses:
 *       201:
 *         description: Invoice created
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Invoice'
 */

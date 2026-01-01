/**
 * Swagger/OpenAPI API Documentation Generator
 * Auto-generates interactive API docs from code
 * Docs stay in sync with actual API
 */

import swaggerJsdoc from "swagger-jsdoc";
import swaggerUi from "swagger-ui-express";
import { Router } from "express";

const router = Router();

/**
 * Swagger configuration
 */
const swaggerOptions = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "Infæmous Freight API",
      version: "1.0.0",
      description:
        "AI-powered freight logistics platform API. Real-time shipment tracking, driver management, and intelligent routing.",
      contact: {
        name: "API Support",
        url: "https://infamous-freight.com/support",
        email: "support@infamous-freight.com",
      },
      license: {
        name: "MIT",
        url: "https://opensource.org/licenses/MIT",
      },
    },
    servers: [
      {
        url: "http://localhost:4000",
        description: "Development server",
      },
      {
        url: "https://api.infamous-freight.com",
        description: "Production server",
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT",
          description: "JWT authentication token",
        },
      },
      schemas: {
        Shipment: {
          type: "object",
          properties: {
            id: { type: "string", description: "Unique shipment ID" },
            trackingNumber: {
              type: "string",
              description: "Tracking number (e.g., IFE-12345)",
            },
            status: {
              type: "string",
              enum: ["PENDING", "IN_TRANSIT", "DELIVERED", "FAILED"],
            },
            origin: { type: "string", description: "Origin address" },
            destination: { type: "string", description: "Destination address" },
            weight: { type: "number", description: "Weight in kg" },
            driverId: { type: "string", description: "Assigned driver ID" },
            customerId: { type: "string", description: "Customer ID" },
            createdAt: { type: "string", format: "date-time" },
            updatedAt: { type: "string", format: "date-time" },
          },
          required: ["trackingNumber", "origin", "destination"],
        },
        Driver: {
          type: "object",
          properties: {
            id: { type: "string" },
            name: { type: "string" },
            email: { type: "string" },
            phone: { type: "string" },
            status: {
              type: "string",
              enum: ["AVAILABLE", "ON_DUTY", "OFF_DUTY"],
            },
            vehicle: { type: "string", description: "Vehicle license plate" },
          },
        },
        ApiResponse: {
          type: "object",
          properties: {
            success: { type: "boolean" },
            data: { type: "object" },
            error: { type: "string" },
            message: { type: "string" },
          },
        },
      },
    },
    security: [
      {
        bearerAuth: [],
      },
    ],
  },
  apis: [
    // Point to route files with JSDoc comments
    "./src/routes/shipments.ts",
    "./src/routes/drivers.ts",
    "./src/routes/webhooks.ts",
    "./src/routes/health.ts",
  ],
};

// Generate swagger spec
const swaggerSpec = swaggerJsdoc(swaggerOptions);

// Serve Swagger UI
router.use(
  "/docs",
  swaggerUi.serve,
  swaggerUi.setup(swaggerSpec, {
    swaggerOptions: {
      supportedSubmitMethods: ["get", "post", "put", "patch", "delete"],
      defaultModelsExpandDepth: 2,
      defaultModelExpandDepth: 1,
    },
  }),
);

// Serve raw OpenAPI spec
router.get("/openapi.json", (req, res) => {
  res.setHeader("Content-Type", "application/json");
  res.send(swaggerSpec);
});

export default router;

/**
 * Example JSDoc comments for routes:
 *
 * **GET /api/shipments/:id - Get shipment by ID:**
 *
 * /**
 *  * @swagger
 *  * /api/shipments/{id}:
 *  *   get:
 *  *     summary: Get shipment details
 *  *     description: Retrieve full details of a shipment including location and driver info
 *  *     tags:
 *  *       - Shipments
 *  *     parameters:
 *  *       - in: path
 *  *         name: id
 *  *         required: true
 *  *         schema:
 *  *           type: string
 *  *         description: Shipment ID
 *  *     responses:
 *  *       200:
 *  *         description: Shipment details
 *  *         content:
 *  *           application/json:
 *  *             schema:
 *  *               $ref: '#/components/schemas/Shipment'
 *  *       404:
 *  *         description: Shipment not found
 *  *       401:
 *  *         description: Unauthorized
 *  *     security:
 *  *       - bearerAuth: []
 *  * /
 *
 * **POST /api/shipments - Create shipment:**
 *
 * /**
 *  * @swagger
 *  * /api/shipments:
 *  *   post:
 *  *     summary: Create new shipment
 *  *     description: Create a new shipment with origin, destination, and weight
 *  *     tags:
 *  *       - Shipments
 *  *     requestBody:
 *  *       required: true
 *  *       content:
 *  *         application/json:
 *  *           schema:
 *  *             type: object
 *  *             properties:
 *  *               trackingNumber:
 *  *                 type: string
 *  *               origin:
 *  *                 type: string
 *  *               destination:
 *  *                 type: string
 *  *               weight:
 *  *                 type: number
 *  *             required: [trackingNumber, origin, destination, weight]
 *  *     responses:
 *  *       201:
 *  *         description: Shipment created
 *  *         content:
 *  *           application/json:
 *  *             schema:
 *  *               $ref: '#/components/schemas/Shipment'
 *  *       400:
 *  *         description: Invalid input
 *  *     security:
 *  *       - bearerAuth: []
 *  * /
 *
 * Benefits:
 * - Interactive API testing (Swagger UI)
 * - Auto-generates OpenAPI spec
 * - Stays in sync with code
 * - API consumers have clear documentation
 * - Supports code generation (OpenAPI Generator)
 * - Standard format (OpenAPI 3.0)
 *
 * Setup:
 * npm install swagger-jsdoc swagger-ui-express
 *
 * Usage:
 * app.use('/api-docs', apiDocsRouter);
 * // Now visit http://localhost:4000/api-docs
 */

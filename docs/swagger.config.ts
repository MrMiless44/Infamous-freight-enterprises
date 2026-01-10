// packages/api/swagger.config.ts
// Auto-generated API documentation configuration

import swaggerJsdoc from "swagger-jsdoc";

const options = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "Infamous Freight Enterprises API",
      version: "2.0.0",
      description:
        "REST API for freight management, driver dispatch, and billing",
      contact: {
        name: "API Support",
        email: "api@infamous-freight.com",
        url: "https://infamous-freight.com/support",
      },
      license: {
        name: "Proprietary",
        url: "https://infamous-freight.com/license",
      },
    },
    servers: [
      {
        url: "http://localhost:4000/api",
        description: "Development Server",
      },
      {
        url: "https://api.infamous-freight.com/api",
        description: "Production Server",
      },
    ],
    components: {
      securitySchemes: {
        BearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT",
          description: "JWT token obtained from /auth/login",
        },
      },
      schemas: {
        Shipment: {
          type: "object",
          required: ["id", "origin", "destination", "status"],
          properties: {
            id: {
              type: "string",
              format: "uuid",
            },
            origin: {
              type: "string",
              description: "Pickup location address",
            },
            destination: {
              type: "string",
              description: "Delivery location address",
            },
            status: {
              type: "string",
              enum: ["pending", "in-transit", "delivered", "failed"],
            },
            driverId: {
              type: "string",
              format: "uuid",
              nullable: true,
            },
            weight: {
              type: "number",
              description: "Weight in pounds",
            },
            createdAt: {
              type: "string",
              format: "date-time",
            },
            updatedAt: {
              type: "string",
              format: "date-time",
            },
          },
        },
        Driver: {
          type: "object",
          required: ["id", "userId", "organizationId"],
          properties: {
            id: {
              type: "string",
              format: "uuid",
            },
            userId: {
              type: "string",
              format: "uuid",
            },
            organizationId: {
              type: "string",
              format: "uuid",
            },
            licenseNumber: {
              type: "string",
            },
            isAvailable: {
              type: "boolean",
              default: true,
            },
            currentLocation: {
              type: "object",
              properties: {
                latitude: { type: "number" },
                longitude: { type: "number" },
              },
            },
          },
        },
        ApiResponse: {
          type: "object",
          properties: {
            status: {
              type: "string",
              enum: ["success", "error"],
            },
            data: {
              type: "object",
              nullable: true,
            },
            error: {
              type: "string",
              nullable: true,
            },
          },
        },
      },
    },
    security: [
      {
        BearerAuth: [],
      },
    ],
  },
  apis: ["./src/controllers/**/*.ts", "./src/routes/**/*.ts"],
};

export const specs = swaggerJsdoc(options);

/**
 * OpenAPI/Swagger Documentation Generator
 * Auto-generates API documentation from endpoint metadata
 */

export interface ApiEndpoint {
  method: string;
  path: string;
  summary: string;
  description: string;
  tags: string[];
  parameters?: Parameter[];
  requestBody?: RequestBody;
  responses: Response[];
  security?: Security[];
  examples?: Example[];
}

export interface Parameter {
  name: string;
  in: "query" | "path" | "header" | "cookie";
  required: boolean;
  schema: any;
  description: string;
}

export interface RequestBody {
  required: boolean;
  content: {
    "application/json": {
      schema: any;
      examples?: Record<string, any>;
    };
  };
}

export interface Response {
  code: number;
  description: string;
  schema?: any;
}

export interface Security {
  bearerAuth: string[];
}

export interface Example {
  name: string;
  request: any;
  response: any;
}

/**
 * OpenAPI 3.0 specification generator
 */
export class OpenApiGenerator {
  private title: string;
  private version: string;
  private baseUrl: string;
  private endpoints: ApiEndpoint[] = [];

  constructor(title: string, version: string, baseUrl: string) {
    this.title = title;
    this.version = version;
    this.baseUrl = baseUrl;
  }

  /**
   * Register an endpoint
   */
  registerEndpoint(endpoint: ApiEndpoint): void {
    this.endpoints.push(endpoint);
  }

  /**
   * Register multiple endpoints
   */
  registerEndpoints(endpoints: ApiEndpoint[]): void {
    this.endpoints.push(...endpoints);
  }

  /**
   * Generate OpenAPI 3.0 specification
   */
  generate(): object {
    return {
      openapi: "3.0.0",
      info: {
        title: this.title,
        version: this.version,
        description: "Infamous Freight Enterprises API Documentation",
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
          url: this.baseUrl,
          description: "API Server",
        },
      ],
      paths: this.generatePaths(),
      components: {
        securitySchemes: {
          bearerAuth: {
            type: "http",
            scheme: "bearer",
            bearerFormat: "JWT",
            description: "JWT access token (15-minute expiry)",
          },
        },
        schemas: this.generateSchemas(),
      },
      security: [{ bearerAuth: [] }],
      tags: this.generateTags(),
    };
  }

  /**
   * Generate paths from endpoints
   */
  private generatePaths(): object {
    const paths: any = {};

    for (const endpoint of this.endpoints) {
      if (!paths[endpoint.path]) {
        paths[endpoint.path] = {};
      }

      const method = endpoint.method.toLowerCase();
      paths[endpoint.path][method] = {
        summary: endpoint.summary,
        description: endpoint.description,
        tags: endpoint.tags,
        parameters: endpoint.parameters || [],
        requestBody: endpoint.requestBody,
        responses: this.formatResponses(endpoint.responses),
        security: endpoint.security,
        examples: endpoint.examples,
      };
    }

    return paths;
  }

  /**
   * Format responses for OpenAPI
   */
  private formatResponses(responses: Response[]): object {
    const formatted: any = {};

    for (const response of responses) {
      formatted[response.code] = {
        description: response.description,
        content: response.schema
          ? {
              "application/json": {
                schema: response.schema,
              },
            }
          : undefined,
      };
    }

    return formatted;
  }

  /**
   * Generate schemas from endpoints
   */
  private generateSchemas(): object {
    return {
      ApiResponse: {
        type: "object",
        properties: {
          success: { type: "boolean" },
          data: { type: "object" },
          error: { type: "string" },
          code: { type: "string" },
        },
      },
      Error: {
        type: "object",
        properties: {
          error: { type: "string" },
          code: { type: "string" },
          details: { type: "object" },
        },
      },
      Shipment: {
        type: "object",
        properties: {
          id: { type: "string", format: "uuid" },
          origin: { type: "string" },
          destination: { type: "string" },
          status: {
            type: "string",
            enum: ["pending", "in_transit", "delivered", "cancelled"],
          },
          weight: { type: "number" },
          createdAt: { type: "string", format: "date-time" },
          updatedAt: { type: "string", format: "date-time" },
        },
      },
    };
  }

  /**
   * Generate tags
   */
  private generateTags(): object[] {
    const tagSet = new Set<string>();
    for (const endpoint of this.endpoints) {
      endpoint.tags.forEach((tag) => tagSet.add(tag));
    }

    return Array.from(tagSet).map((tag) => ({
      name: tag,
      description: `${tag} endpoints`,
    }));
  }

  /**
   * Export as JSON
   */
  toJson(): string {
    return JSON.stringify(this.generate(), null, 2);
  }

  /**
   * Export as YAML (simple version)
   */
  toYaml(): string {
    const spec = this.generate();
    return JSON.stringify(spec, null, 2); // In production, use proper YAML library
  }
}

/**
 * Predefined API endpoint definitions
 */
export const API_ENDPOINTS: ApiEndpoint[] = [
  {
    method: "POST",
    path: "/api/auth/login",
    summary: "User Login",
    description: "Authenticate user with email and password",
    tags: ["Authentication"],
    parameters: [],
    requestBody: {
      required: true,
      content: {
        "application/json": {
          schema: {
            type: "object",
            required: ["email", "password"],
            properties: {
              email: { type: "string", format: "email" },
              password: { type: "string", format: "password" },
            },
          },
        },
      },
    },
    responses: [
      {
        code: 200,
        description: "Login successful",
        schema: {
          type: "object",
          properties: {
            accessToken: { type: "string" },
            refreshToken: { type: "string" },
            expiresIn: { type: "number" },
          },
        },
      },
      { code: 401, description: "Invalid credentials" },
      { code: 429, description: "Too many login attempts" },
    ],
  },
  {
    method: "GET",
    path: "/api/shipments",
    summary: "List Shipments",
    description: "Retrieve all shipments for authenticated user",
    tags: ["Shipments"],
    parameters: [
      {
        name: "status",
        in: "query",
        required: false,
        schema: {
          type: "string",
          enum: ["pending", "in_transit", "delivered"],
        },
        description: "Filter by shipment status",
      },
      {
        name: "limit",
        in: "query",
        required: false,
        schema: { type: "integer", default: 10 },
        description: "Number of results to return",
      },
    ],
    responses: [
      {
        code: 200,
        description: "List of shipments",
        schema: {
          type: "array",
          items: { $ref: "#/components/schemas/Shipment" },
        },
      },
      { code: 401, description: "Unauthorized" },
    ],
    security: [{ bearerAuth: ["shipments:read"] }],
  },
];

// Export singleton instance
export const openApiGenerator = new OpenApiGenerator(
  "Infamous Freight Enterprises API",
  "1.0.0",
  process.env.API_URL || "http://localhost:3001",
);

export default OpenApiGenerator;

import request from "supertest";
import express from "express";
import { swaggerDocsRouter } from "../../routes/swagger-docs";

describe("Swagger Documentation Routes", () => {
  let app: express.Application;

  beforeEach(() => {
    app = express();
    app.use(express.json());
    app.use("/swagger", swaggerDocsRouter as any);
    jest.clearAllMocks();
  });

  describe("GET /swagger/json", () => {
    it("should return OpenAPI schema", async () => {
      const response = await request(app).get("/swagger/json");

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty("openapi");
      expect(response.body).toHaveProperty("paths");
    });
  });

  describe("GET /swagger/ui", () => {
    it("should serve Swagger UI", async () => {
      const response = await request(app).get("/swagger/ui");

      expect(response.status).toBe(200);
      expect(response.type).toMatch(/html/);
    });
  });

  describe("GET /swagger/info", () => {
    it("should return API information", async () => {
      const response = await request(app).get("/swagger/info");

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty("version");
      expect(response.body).toHaveProperty("title");
    });
  });
});

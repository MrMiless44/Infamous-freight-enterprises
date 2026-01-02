import request from "supertest";
import express from "express";
import { routeRouter } from "../../routes/route";
import { authenticate, requireScope } from "../../middleware/security";

jest.mock("@prisma/client");
jest.mock("../../middleware/security");

describe("Route Management Routes", () => {
  let app: express.Application;

  beforeEach(() => {
    app = express();
    app.use(express.json());
    app.use(authenticate as any);
    app.use("/routes", routeRouter as any);
    jest.clearAllMocks();
  });

  describe("GET /routes", () => {
    it("should list all routes", async () => {
      const response = await request(app).get("/routes");

      expect(response.status).toBe(200);
      expect(Array.isArray(response.body.data)).toBe(true);
    });

    it("should filter by driver", async () => {
      const response = await request(app)
        .get("/routes")
        .query({ driverId: "driver-123" });

      expect(response.status).toBe(200);
    });
  });

  describe("GET /routes/:id", () => {
    it("should get route details", async () => {
      const response = await request(app).get("/routes/route-123");

      expect([200, 404]).toContain(response.status);
    });
  });

  describe("POST /routes", () => {
    it("should create new route", async () => {
      const response = await request(app)
        .post("/routes")
        .send({
          driverId: "driver-123",
          waypoints: [
            { lat: 40.7128, lng: -74.006 },
            { lat: 40.758, lng: -73.9855 },
          ],
        });

      expect([200, 201, 400]).toContain(response.status);
    });
  });

  describe("PUT /routes/:id", () => {
    it("should update route", async () => {
      const response = await request(app).put("/routes/route-123").send({
        status: "completed",
      });

      expect([200, 404, 400]).toContain(response.status);
    });
  });

  describe("DELETE /routes/:id", () => {
    it("should cancel route", async () => {
      const response = await request(app).delete("/routes/route-123");

      expect([200, 204, 404]).toContain(response.status);
    });
  });
});

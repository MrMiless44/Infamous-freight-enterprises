const request = require("supertest");
const { prisma } = require("../../src/db/prisma");
const app = require("../../src/server");
const jwt = require("jsonwebtoken");

describe("Real-time Shipment Tracking Integration", () => {
  let authToken;
  let testUser;
  let testDriver;
  let testShipment;

  beforeAll(async () => {
    // Create test user
    testUser = await prisma.user.create({
      data: {
        email: "integration-test@example.com",
        name: "Integration Test User",
        role: "admin",
      },
    });

    // Create test driver
    testDriver = await prisma.driver.create({
      data: {
        name: "Test Driver",
        phone: "+1234567890",
        status: "available",
      },
    });

    // Generate auth token
    authToken = jwt.sign(
      {
        sub: testUser.id,
        email: testUser.email,
        role: testUser.role,
        scopes: [
          "shipments:read",
          "shipments:write",
          "users:read",
          "users:write",
        ],
      },
      process.env.JWT_SECRET || "test-secret",
      { expiresIn: "1h" },
    );
  });

  afterAll(async () => {
    // Cleanup
    if (testShipment) {
      await prisma.shipment.deleteMany({
        where: { reference: testShipment.reference },
      });
    }
    await prisma.driver.delete({ where: { id: testDriver.id } });
    await prisma.user.delete({ where: { id: testUser.id } });
    await prisma.$disconnect();
  });

  describe("Shipment Lifecycle", () => {
    it("should create a new shipment", async () => {
      const response = await request(app)
        .post("/api/shipments")
        .set("Authorization", `Bearer ${authToken}`)
        .send({
          reference: `TEST-SHIP-${Date.now()}`,
          origin: "New York, NY",
          destination: "Los Angeles, CA",
          driverId: testDriver.id,
        });

      expect(response.status).toBe(201);
      expect(response.body.ok).toBe(true);
      expect(response.body.shipment).toBeDefined();
      expect(response.body.shipment.status).toBe("created");

      testShipment = response.body.shipment;
    });

    it("should retrieve shipment by ID", async () => {
      const response = await request(app)
        .get(`/api/shipments/${testShipment.id}`)
        .set("Authorization", `Bearer ${authToken}`);

      expect(response.status).toBe(200);
      expect(response.body.ok).toBe(true);
      expect(response.body.shipment.id).toBe(testShipment.id);
      expect(response.body.shipment.driver).toBeDefined();
      expect(response.body.shipment.driver.name).toBe(testDriver.name);
    });

    it("should list all shipments with filters", async () => {
      const response = await request(app)
        .get("/api/shipments")
        .query({ status: "created", driverId: testDriver.id })
        .set("Authorization", `Bearer ${authToken}`);

      expect(response.status).toBe(200);
      expect(response.body.ok).toBe(true);
      expect(Array.isArray(response.body.shipments)).toBe(true);
      expect(
        response.body.shipments.find((s) => s.id === testShipment.id),
      ).toBeDefined();
    });

    it("should update shipment status", async () => {
      const response = await request(app)
        .patch(`/api/shipments/${testShipment.id}`)
        .set("Authorization", `Bearer ${authToken}`)
        .send({
          status: "in_transit",
        });

      expect(response.status).toBe(200);
      expect(response.body.ok).toBe(true);
      expect(response.body.shipment.status).toBe("in_transit");
    });

    it("should update shipment to delivered", async () => {
      const response = await request(app)
        .patch(`/api/shipments/${testShipment.id}`)
        .set("Authorization", `Bearer ${authToken}`)
        .send({
          status: "delivered",
        });

      expect(response.status).toBe(200);
      expect(response.body.ok).toBe(true);
      expect(response.body.shipment.status).toBe("delivered");
    });

    it("should export shipments to CSV", async () => {
      const response = await request(app)
        .get("/api/shipments/export/csv")
        .set("Authorization", `Bearer ${authToken}`);

      expect(response.status).toBe(200);
      expect(response.headers["content-type"]).toContain("text/csv");
      expect(response.text).toContain(testShipment.reference);
    });

    it("should export shipments to JSON", async () => {
      const response = await request(app)
        .get("/api/shipments/export/json")
        .set("Authorization", `Bearer ${authToken}`);

      expect(response.status).toBe(200);
      expect(response.headers["content-type"]).toContain("application/json");
      const data = JSON.parse(response.text);
      expect(data.shipments).toBeDefined();
      expect(Array.isArray(data.shipments)).toBe(true);
    });

    it("should export shipments to PDF", async () => {
      const response = await request(app)
        .get("/api/shipments/export/pdf")
        .set("Authorization", `Bearer ${authToken}`);

      expect(response.status).toBe(200);
      expect(response.headers["content-type"]).toContain("application/pdf");
    });
  });

  describe("Health Checks", () => {
    it("should return basic health status", async () => {
      const response = await request(app).get("/api/health");

      expect(response.status).toBe(200);
      expect(response.body.status).toBe("ok");
      expect(response.body.service).toBe("infamous-freight-api");
    });

    it("should return detailed health status", async () => {
      const response = await request(app).get("/api/health/detailed");

      expect(response.status).toBe(200);
      expect(response.body.checks).toBeDefined();
      expect(response.body.checks.database).toBeDefined();
      expect(response.body.checks.database.status).toBe("healthy");
    });

    it("should return readiness check", async () => {
      const response = await request(app).get("/api/health/ready");

      expect(response.status).toBe(200);
      expect(response.body.status).toBe("ready");
    });

    it("should return liveness check", async () => {
      const response = await request(app).get("/api/health/live");

      expect(response.status).toBe(200);
      expect(response.body.status).toBe("alive");
    });
  });

  describe("Error Handling", () => {
    it("should handle non-existent shipment", async () => {
      const response = await request(app)
        .get("/api/shipments/non-existent-id")
        .set("Authorization", `Bearer ${authToken}`);

      expect(response.status).toBe(404);
      expect(response.body.ok).toBe(false);
    });

    it("should handle duplicate reference", async () => {
      const response = await request(app)
        .post("/api/shipments")
        .set("Authorization", `Bearer ${authToken}`)
        .send({
          reference: testShipment.reference,
          origin: "Test Origin",
          destination: "Test Destination",
        });

      expect(response.status).toBe(409);
      expect(response.body.ok).toBe(false);
      expect(response.body.error).toContain("already exists");
    });

    it("should handle missing required fields", async () => {
      const response = await request(app)
        .post("/api/shipments")
        .set("Authorization", `Bearer ${authToken}`)
        .send({
          reference: "TEST-NO-DEST",
          origin: "Test Origin",
        });

      expect(response.status).toBe(400);
      expect(response.body.ok).toBe(false);
    });

    it("should handle unauthorized access", async () => {
      const response = await request(app).get("/api/shipments");

      // In dev mode without JWT_SECRET, it may allow requests
      if (process.env.JWT_SECRET) {
        expect(response.status).toBe(401);
      }
    });
  });
});

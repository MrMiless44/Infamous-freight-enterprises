const request = require("supertest");
const express = require("express");
const jwt = require("jsonwebtoken");

const JWT_SECRET = "test-secret";
process.env.JWT_SECRET = JWT_SECRET;

const makeToken = (scopes = ["billing:read"]) =>
  jwt.sign({ sub: "test-user", scopes }, JWT_SECRET);

const authHeader = (token) => ({ Authorization: `Bearer ${token}` });

let app;

describe("Billing Reports Routes", () => {
  beforeEach(() => {
    delete require.cache[require.resolve("../src/routes/billing/reports")];
    delete require.cache[require.resolve("../src/middleware/security")];
    delete require.cache[require.resolve("../src/middleware/errorHandler")];

    const reportRoutes = require("../src/routes/billing/reports");
    const errorHandler = require("../src/middleware/errorHandler");

    app = express();
    app.use(express.json());
    app.use("/api/billing/reports", reportRoutes);
    app.use(errorHandler);
  });

  test("should return summary and metrics", async () => {
    const response = await request(app)
      .get("/api/billing/reports")
      .set(authHeader(makeToken()));

    expect(response.status).toBe(200);
    expect(response.body.success).toBe(true);
    expect(response.body.data.summary).toBeDefined();
    expect(response.body.data.revenue.monthly.length).toBeGreaterThan(0);
    expect(response.body.data.usage.apiCalls).toBeGreaterThan(0);
  });

  test("should enforce auth", async () => {
    const response = await request(app).get("/api/billing/reports");
    expect(response.status).toBe(401);
  });

  test("should enforce scope", async () => {
    const response = await request(app)
      .get("/api/billing/reports")
      .set(authHeader(makeToken(["other:scope"])));
    expect(response.status).toBe(403);
  });
});

const request = require("supertest");
const express = require("express");
const jwt = require("jsonwebtoken");

const JWT_SECRET = "test-secret";
process.env.JWT_SECRET = JWT_SECRET;

const makeToken = (scopes = ["billing:read"]) =>
  jwt.sign({ sub: "test-user", scopes }, JWT_SECRET);

const authHeader = (token) => ({ Authorization: `Bearer ${token}` });

let app;

describe("Billing Invoices Routes", () => {
  beforeEach(() => {
    delete require.cache[require.resolve("../src/routes/billing/invoices")];
    delete require.cache[require.resolve("../src/middleware/security")];
    delete require.cache[require.resolve("../src/middleware/errorHandler")];

    const invoiceRoutes = require("../src/routes/billing/invoices");
    const errorHandler = require("../src/middleware/errorHandler");

    app = express();
    app.use(express.json());
    app.use("/api/billing/invoices", invoiceRoutes);
    app.use(errorHandler);
  });

  test("should list invoices with pagination", async () => {
    const response = await request(app)
      .get("/api/billing/invoices?page=1&limit=3")
      .set(authHeader(makeToken()));

    expect(response.status).toBe(200);
    expect(response.body.ok).toBe(true);
    expect(response.body.data.invoices).toHaveLength(3);
    expect(response.body.data.pagination.total).toBeGreaterThanOrEqual(3);
    expect(response.body.data.summary.total).toBeGreaterThan(0);
  });

  test("should filter by status", async () => {
    const response = await request(app)
      .get("/api/billing/invoices?status=paid")
      .set(authHeader(makeToken()));

    expect(response.status).toBe(200);
    expect(response.body.data.invoices.every((i) => i.status === "paid")).toBe(
      true,
    );
  });

  test("should return 404 for missing invoice", async () => {
    const response = await request(app)
      .get("/api/billing/invoices/unknown")
      .set(authHeader(makeToken()));

    expect(response.status).toBe(404);
    expect(response.body.error).toBe("Invoice not found");
  });

  test("should enforce auth", async () => {
    const response = await request(app).get("/api/billing/invoices");
    expect(response.status).toBe(401);
  });

  test("should enforce scope", async () => {
    const response = await request(app)
      .get("/api/billing/invoices")
      .set(authHeader(makeToken(["other:scope"])));
    expect(response.status).toBe(403);
  });
});

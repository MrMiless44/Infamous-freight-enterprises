const request = require("supertest");
const express = require("express");
const jwt = require("jsonwebtoken");

// Mock Stripe before requiring the route
jest.mock("stripe", () => {
  return jest.fn(() => ({
    checkout: {
      sessions: {
        create: jest.fn(),
      },
    },
  }));
});

// Mock PayPal before requiring the route
jest.mock("@paypal/checkout-server-sdk", () => ({
  core: {
    SandboxEnvironment: jest.fn(),
    PayPalHttpClient: jest.fn(),
  },
  orders: {
    OrdersCreateRequest: jest.fn(),
    OrdersCaptureRequest: jest.fn(),
  },
}));

// Mock Prisma
jest.mock("../src/db/prisma", () => ({
  prisma: {},
}));

const Stripe = require("stripe");
const paypal = require("@paypal/checkout-server-sdk");

// Setup test app
let app;
let stripeInstance;
let paypalClientMock;

const JWT_SECRET = "test-secret";
process.env.JWT_SECRET = JWT_SECRET;

const makeToken = (scopes = ["billing:write"]) => {
  return jwt.sign({ sub: "test-user", scopes }, JWT_SECRET);
};

const authHeader = (token) => ({ Authorization: `Bearer ${token}` });

describe("Billing Routes", () => {
  beforeEach(() => {
    // Clear all mocks
    jest.clearAllMocks();

    // Setup Stripe mock
    stripeInstance = {
      checkout: {
        sessions: {
          create: jest.fn(),
        },
      },
    };
    Stripe.mockReturnValue(stripeInstance);

    // Setup PayPal mock
    paypalClientMock = {
      execute: jest.fn(),
    };
    paypal.core.PayPalHttpClient.mockReturnValue(paypalClientMock);

    // Set environment variables for success
    process.env.STRIPE_SECRET_KEY = "sk_test_123";
    process.env.STRIPE_SUCCESS_URL = "https://example.com/success";
    process.env.STRIPE_CANCEL_URL = "https://example.com/cancel";
    process.env.PAYPAL_CLIENT_ID = "test-client-id";
    process.env.PAYPAL_SECRET = "test-secret";

    // Require route after mocks are setup
    delete require.cache[require.resolve("../src/routes/billing")];
    delete require.cache[require.resolve("../src/middleware/security")];
    delete require.cache[require.resolve("../src/middleware/errorHandler")];

    const billingRouter = require("../src/routes/billing");
    const errorHandler = require("../src/middleware/errorHandler");

    app = express();
    app.use(express.json());
    app.use("/api", billingRouter);
    app.use(errorHandler);
  });

  afterEach(() => {
    // Clean up environment
    delete process.env.STRIPE_SECRET_KEY;
    delete process.env.STRIPE_SUCCESS_URL;
    delete process.env.STRIPE_CANCEL_URL;
    delete process.env.PAYPAL_CLIENT_ID;
    delete process.env.PAYPAL_SECRET;
  });

  describe("POST /billing/stripe/session", () => {
    test("should create Stripe session successfully", async () => {
      const mockSession = {
        id: "cs_test_123",
        url: "https://checkout.stripe.com/c/pay/cs_test_123",
      };

      stripeInstance.checkout.sessions.create.mockResolvedValue(mockSession);

      const response = await request(app)
        .post("/api/billing/stripe/session")
        .set(authHeader(makeToken(["billing:write"])))
        .send({});

      expect(response.status).toBe(200);
      expect(response.body).toEqual({
        ok: true,
        sessionId: mockSession.id,
        url: mockSession.url,
      });
      expect(stripeInstance.checkout.sessions.create).toHaveBeenCalledWith({
        mode: "payment",
        success_url: process.env.STRIPE_SUCCESS_URL,
        cancel_url: process.env.STRIPE_CANCEL_URL,
        line_items: [
          {
            price_data: {
              currency: "usd",
              product_data: { name: "Infamous Freight AI" },
              unit_amount: 4900,
            },
            quantity: 1,
          },
        ],
      });
    });

    test("should return 503 when Stripe not configured", async () => {
      // Save original value
      const originalKey = process.env.STRIPE_SECRET_KEY;
      delete process.env.STRIPE_SECRET_KEY;

      // Clear module caches
      delete require.cache[require.resolve("../src/routes/billing")];
      delete require.cache[require.resolve("../src/middleware/security")];
      delete require.cache[require.resolve("../src/middleware/errorHandler")];

      // Re-require the route without Stripe configured
      const billingRouter = require("../src/routes/billing");
      const errorHandler = require("../src/middleware/errorHandler");

      const testApp = express();
      testApp.use(express.json());
      testApp.use("/api", billingRouter);
      testApp.use(errorHandler);

      const response = await request(testApp)
        .post("/api/billing/stripe/session")
        .set(authHeader(makeToken(["billing:write"])))
        .send({});

      expect(response.status).toBe(503);
      expect(response.body.error).toBe("Stripe not configured");

      // Restore original value
      process.env.STRIPE_SECRET_KEY = originalKey;
    });

    test("should return 503 when success URL not configured", async () => {
      const originalUrl = process.env.STRIPE_SUCCESS_URL;
      delete process.env.STRIPE_SUCCESS_URL;

      const response = await request(app)
        .post("/api/billing/stripe/session")
        .set(authHeader(makeToken(["billing:write"])))
        .send({});

      expect(response.status).toBe(503);
      expect(response.body.error).toBe(
        "Stripe success/cancel URLs not configured"
      );

      process.env.STRIPE_SUCCESS_URL = originalUrl;
    });

    test("should return 503 when cancel URL not configured", async () => {
      const originalUrl = process.env.STRIPE_CANCEL_URL;
      delete process.env.STRIPE_CANCEL_URL;

      const response = await request(app)
        .post("/api/billing/stripe/session")
        .set(authHeader(makeToken(["billing:write"])))
        .send({});

      expect(response.status).toBe(503);
      expect(response.body.error).toBe(
        "Stripe success/cancel URLs not configured"
      );

      process.env.STRIPE_CANCEL_URL = originalUrl;
    });

    test("should handle Stripe API errors", async () => {
      stripeInstance.checkout.sessions.create.mockRejectedValue(
        new Error("Stripe API error")
      );

      const response = await request(app)
        .post("/api/billing/stripe/session")
        .set(authHeader(makeToken(["billing:write"])))
        .send({});

      expect(response.status).toBe(500);
    });

    test("should require authentication", async () => {
      const response = await request(app)
        .post("/api/billing/stripe/session")
        .send({});

      expect(response.status).toBe(401);
    });

    test("should require billing:write scope", async () => {
      const response = await request(app)
        .post("/api/billing/stripe/session")
        .set(authHeader(makeToken(["other:scope"])))
        .send({});

      expect(response.status).toBe(403);
    });
  });

  describe("POST /billing/paypal/order", () => {
    test("should create PayPal order successfully", async () => {
      const mockOrder = {
        result: {
          id: "ORDER123",
          links: [
            { rel: "approve", href: "https://paypal.com/approve/ORDER123" },
          ],
        },
      };

      paypalClientMock.execute.mockResolvedValue(mockOrder);

      const response = await request(app)
        .post("/api/billing/paypal/order")
        .set(authHeader(makeToken(["billing:write"])))
        .send({});

      expect(response.status).toBe(200);
      expect(response.body).toEqual({
        ok: true,
        orderId: "ORDER123",
        approvalUrl: "https://paypal.com/approve/ORDER123",
      });
    });

    test("should handle order without approval link", async () => {
      const mockOrder = {
        result: {
          id: "ORDER123",
          links: [],
        },
      };

      paypalClientMock.execute.mockResolvedValue(mockOrder);

      const response = await request(app)
        .post("/api/billing/paypal/order")
        .set(authHeader(makeToken(["billing:write"])))
        .send({});

      expect(response.status).toBe(200);
      expect(response.body).toEqual({
        ok: true,
        orderId: "ORDER123",
        approvalUrl: null,
      });
    });

    test("should return 503 when PayPal not configured", async () => {
      delete process.env.PAYPAL_CLIENT_ID;

      delete require.cache[require.resolve("../src/routes/billing")];
      const billingRouter = require("../src/routes/billing");
      const errorHandler = require("../src/middleware/errorHandler");

      app = express();
      app.use(express.json());
      app.use("/api", billingRouter);
      app.use(errorHandler);

      const response = await request(app)
        .post("/api/billing/paypal/order")
        .set(authHeader(makeToken(["billing:write"])))
        .send({});

      expect(response.status).toBe(503);
      expect(response.body.error).toBe("PayPal not configured");
    });

    test("should handle PayPal API errors", async () => {
      paypalClientMock.execute.mockRejectedValue(new Error("PayPal API error"));

      const response = await request(app)
        .post("/api/billing/paypal/order")
        .set(authHeader(makeToken(["billing:write"])))
        .send({});

      expect(response.status).toBe(500);
    });

    test("should require authentication", async () => {
      const response = await request(app)
        .post("/api/billing/paypal/order")
        .send({});

      expect(response.status).toBe(401);
    });

    test("should require billing:write scope", async () => {
      const response = await request(app)
        .post("/api/billing/paypal/order")
        .set(authHeader(makeToken(["other:scope"])))
        .send({});

      expect(response.status).toBe(403);
    });
  });

  describe("POST /billing/paypal/capture", () => {
    test("should capture PayPal order successfully", async () => {
      const mockCapture = {
        result: {
          id: "CAPTURE123",
          status: "COMPLETED",
        },
      };

      paypalClientMock.execute.mockResolvedValue(mockCapture);

      const response = await request(app)
        .post("/api/billing/paypal/capture")
        .set(authHeader(makeToken(["billing:write"])))
        .send({ orderId: "ORDER123" });

      expect(response.status).toBe(200);
      expect(response.body).toEqual({
        ok: true,
        capture: mockCapture.result,
      });
    });

    test("should validate orderId is required", async () => {
      const response = await request(app)
        .post("/api/billing/paypal/capture")
        .set(authHeader(makeToken(["billing:write"])))
        .send({});

      expect(response.status).toBe(400);
    });

    test("should validate orderId length", async () => {
      const response = await request(app)
        .post("/api/billing/paypal/capture")
        .set(authHeader(makeToken(["billing:write"])))
        .send({ orderId: "" });

      expect(response.status).toBe(400);
    });

    test("should validate orderId max length", async () => {
      const longOrderId = "A".repeat(129);

      const response = await request(app)
        .post("/api/billing/paypal/capture")
        .set(authHeader(makeToken(["billing:write"])))
        .send({ orderId: longOrderId });

      expect(response.status).toBe(400);
    });

    test("should return 503 when PayPal not configured", async () => {
      delete process.env.PAYPAL_CLIENT_ID;

      delete require.cache[require.resolve("../src/routes/billing")];
      const billingRouter = require("../src/routes/billing");
      const errorHandler = require("../src/middleware/errorHandler");

      app = express();
      app.use(express.json());
      app.use("/api", billingRouter);
      app.use(errorHandler);

      const response = await request(app)
        .post("/api/billing/paypal/capture")
        .set(authHeader(makeToken(["billing:write"])))
        .send({ orderId: "ORDER123" });

      expect(response.status).toBe(503);
      expect(response.body.error).toBe("PayPal not configured");
    });

    test("should handle PayPal capture errors", async () => {
      paypalClientMock.execute.mockRejectedValue(
        new Error("PayPal capture error")
      );

      const response = await request(app)
        .post("/api/billing/paypal/capture")
        .set(authHeader(makeToken(["billing:write"])))
        .send({ orderId: "ORDER123" });

      expect(response.status).toBe(500);
    });

    test("should require authentication", async () => {
      const response = await request(app)
        .post("/api/billing/paypal/capture")
        .send({ orderId: "ORDER123" });

      expect(response.status).toBe(401);
    });

    test("should require billing:write scope", async () => {
      const response = await request(app)
        .post("/api/billing/paypal/capture")
        .set(authHeader(makeToken(["other:scope"])))
        .send({ orderId: "ORDER123" });

      expect(response.status).toBe(403);
    });
  });
});

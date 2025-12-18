const request = require("supertest");
const jwt = require("jsonwebtoken");
const path = require("path");

process.env.JWT_SECRET = "test-secret";
delete process.env.STRIPE_SECRET_KEY;
delete process.env.PAYPAL_CLIENT_ID;
delete process.env.PAYPAL_SECRET;
delete process.env.STRIPE_SUCCESS_URL;
delete process.env.STRIPE_CANCEL_URL;

const app = require("../src/server");

const makeToken = (scopes) =>
  jwt.sign(
    {
      sub: "test-user",
      scopes,
    },
    process.env.JWT_SECRET,
  );

const authHeader = (token) => `Bearer ${token}`;

// Skip supertest tests on Node 22+ (target is Node 20.18.1, CI will run these)
const skipOnNode22 = global.skipSupertestOnNode22 ? describe.skip : describe;

skipOnNode22("Route validation and error handling", () => {
  test("rejects disallowed origins with 403", async () => {
    const res = await request(app)
      .get("/api/health")
      .set("Origin", "http://evil.com");

    expect(res.status).toBe(403);
    expect(res.body.error).toBe("CORS Rejected");
  });

  test("ai command validation fails when command missing", async () => {
    const token = makeToken(["ai:command"]);
    const res = await request(app)
      .post("/api/ai/command")
      .set("Authorization", authHeader(token))
      .send({});

    expect(res.status).toBe(400);
    expect(res.body.error).toBe("Validation Error");
  });

  test("billing stripe session returns 503 when not configured", async () => {
    const token = makeToken(["billing:write"]);
    const res = await request(app)
      .post("/api/billing/stripe/session")
      .set("Authorization", authHeader(token))
      .send({});

    expect(res.status).toBe(503);
    expect(res.body.error).toBe("Stripe not configured");
  });

  test("billing paypal capture requires orderId", async () => {
    const token = makeToken(["billing:write"]);
    const res = await request(app)
      .post("/api/billing/paypal/capture")
      .set("Authorization", authHeader(token))
      .send({});

    expect(res.status).toBe(400);
    expect(res.body.error).toBe("Validation Error");
  });

  test("voice command validation fails when text missing", async () => {
    const token = makeToken(["voice:command"]);
    const res = await request(app)
      .post("/api/voice/command")
      .set("Authorization", authHeader(token))
      .send({});

    expect(res.status).toBe(400);
    expect(res.body.error).toBe("Validation Error");
  });

  test("voice ingest rejects unsupported audio format", async () => {
    const token = makeToken(["voice:ingest"]);
    const res = await request(app)
      .post("/api/voice/ingest")
      .set("Authorization", authHeader(token))
      .attach("audio", Buffer.from("hello"), {
        filename: "test.txt",
        contentType: "text/plain",
      });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe("Validation Error");
    expect(String(res.body.details || res.body.message)).toMatch(
      /Unsupported audio format/,
    );
  });
});

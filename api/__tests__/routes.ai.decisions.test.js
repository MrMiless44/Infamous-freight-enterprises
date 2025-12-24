const request = require("supertest");
const jwt = require("jsonwebtoken");

// Setup test environment
process.env.JWT_SECRET = "test-secret";
process.env.NODE_ENV = "test";

// Mock Prisma with transaction support
jest.mock("../src/db/prisma", () => ({
  prisma: {
    aiDecision: {
      findMany: jest.fn(),
      findUnique: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
    },
    aiFeedback: {
      findUnique: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
    },
  },
}));

const app = require("../src/server");
const { prisma } = require("../src/db/prisma");

// Helper to generate JWT tokens
const makeToken = (scopes) =>
  jwt.sign(
    {
      sub: "test-user-123",
      scopes,
    },
    process.env.JWT_SECRET,
  );

const authHeader = (token) => `Bearer ${token}`;

// Mock AI decision data
const mockDecision = {
  id: "decision-123",
  organizationId: "org-123",
  invoiceId: "invoice-123",
  agent: "billing_audit",
  decision: "approve",
  confidence: 0.95,
  rationale: { reason: "Invoice matches purchase order" },
  createdAt: new Date("2024-01-01T00:00:00.000Z"),
  feedback: null,
};

const mockFeedback = {
  id: "feedback-123",
  aiDecisionId: "decision-123",
  outcome: "correct",
  notes: "Decision was accurate",
  createdAt: new Date("2024-01-02T00:00:00.000Z"),
};

const mockDecisionWithFeedback = {
  ...mockDecision,
  feedback: mockFeedback,
};

describe("AI Decisions API Routes", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe("GET /api/ai-decisions", () => {
    test("returns all AI decisions when authenticated", async () => {
      prisma.aiDecision.findMany.mockResolvedValue([mockDecision]);
      const token = makeToken(["ai:decisions:read"]);

      const res = await request(app)
        .get("/api/ai-decisions")
        .set("Authorization", authHeader(token));

      expect(res.status).toBe(200);
      expect(res.body.ok).toBe(true);
      expect(res.body.decisions).toHaveLength(1);
      expect(res.body.decisions[0]).toMatchObject({
        id: mockDecision.id,
        organizationId: mockDecision.organizationId,
        invoiceId: mockDecision.invoiceId,
      });
    });

    test("filters decisions by organizationId", async () => {
      prisma.aiDecision.findMany.mockResolvedValue([mockDecision]);
      const token = makeToken(["ai:decisions:read"]);

      const res = await request(app)
        .get("/api/ai-decisions?organizationId=org-123")
        .set("Authorization", authHeader(token));

      expect(res.status).toBe(200);
      expect(prisma.aiDecision.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { organizationId: "org-123" },
        }),
      );
    });

    test("filters decisions by agent", async () => {
      prisma.aiDecision.findMany.mockResolvedValue([mockDecision]);
      const token = makeToken(["ai:decisions:read"]);

      const res = await request(app)
        .get("/api/ai-decisions?agent=billing_audit")
        .set("Authorization", authHeader(token));

      expect(res.status).toBe(200);
      expect(prisma.aiDecision.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { agent: "billing_audit" },
        }),
      );
    });

    test("filters decisions by invoiceId", async () => {
      prisma.aiDecision.findMany.mockResolvedValue([mockDecision]);
      const token = makeToken(["ai:decisions:read"]);

      const res = await request(app)
        .get("/api/ai-decisions?invoiceId=invoice-123")
        .set("Authorization", authHeader(token));

      expect(res.status).toBe(200);
      expect(prisma.aiDecision.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { invoiceId: "invoice-123" },
        }),
      );
    });

    test("requires authentication", async () => {
      const res = await request(app).get("/api/ai-decisions");

      expect(res.status).toBe(401);
    });

    test("requires correct scope", async () => {
      const token = makeToken(["wrong:scope"]);

      const res = await request(app)
        .get("/api/ai-decisions")
        .set("Authorization", authHeader(token));

      expect(res.status).toBe(403);
    });
  });

  describe("GET /api/ai-decisions/:id", () => {
    test("returns specific AI decision by ID", async () => {
      prisma.aiDecision.findUnique.mockResolvedValue(mockDecisionWithFeedback);
      const token = makeToken(["ai:decisions:read"]);

      const res = await request(app)
        .get("/api/ai-decisions/decision-123")
        .set("Authorization", authHeader(token));

      expect(res.status).toBe(200);
      expect(res.body.ok).toBe(true);
      expect(res.body.decision.id).toBe("decision-123");
      expect(res.body.decision.feedback).toBeDefined();
      expect(prisma.aiDecision.findUnique).toHaveBeenCalledWith({
        where: { id: "decision-123" },
        include: { feedback: true },
      });
    });

    test("returns 404 for non-existent decision", async () => {
      prisma.aiDecision.findUnique.mockResolvedValue(null);
      const token = makeToken(["ai:decisions:read"]);

      const res = await request(app)
        .get("/api/ai-decisions/nonexistent")
        .set("Authorization", authHeader(token));

      expect(res.status).toBe(404);
      expect(res.body.ok).toBe(false);
      expect(res.body.error).toBe("AI decision not found");
    });

    test("requires authentication", async () => {
      const res = await request(app).get("/api/ai-decisions/decision-123");

      expect(res.status).toBe(401);
    });
  });

  describe("POST /api/ai-decisions", () => {
    test("creates new AI decision with valid data", async () => {
      prisma.aiDecision.create.mockResolvedValue(mockDecision);
      const token = makeToken(["ai:decisions:write"]);

      const newDecision = {
        organizationId: "org-123",
        invoiceId: "invoice-123",
        agent: "billing_audit",
        decision: "approve",
        confidence: 0.95,
        rationale: { reason: "Invoice matches purchase order" },
      };

      const res = await request(app)
        .post("/api/ai-decisions")
        .set("Authorization", authHeader(token))
        .send(newDecision);

      expect(res.status).toBe(201);
      expect(res.body.ok).toBe(true);
      expect(res.body.decision).toMatchObject({
        organizationId: newDecision.organizationId,
        invoiceId: newDecision.invoiceId,
        agent: newDecision.agent,
        decision: newDecision.decision,
        confidence: newDecision.confidence,
      });
      expect(prisma.aiDecision.create).toHaveBeenCalledWith({
        data: {
          organizationId: newDecision.organizationId,
          invoiceId: newDecision.invoiceId,
          agent: newDecision.agent,
          decision: newDecision.decision,
          confidence: newDecision.confidence,
          rationale: newDecision.rationale,
        },
        include: { feedback: true },
      });
    });

    test("validates confidence is between 0 and 1", async () => {
      const token = makeToken(["ai:decisions:write"]);

      const invalidDecision = {
        organizationId: "org-123",
        invoiceId: "invoice-123",
        agent: "billing_audit",
        decision: "approve",
        confidence: 1.5,
        rationale: {},
      };

      const res = await request(app)
        .post("/api/ai-decisions")
        .set("Authorization", authHeader(token))
        .send(invalidDecision);

      expect(res.status).toBe(400);
      expect(res.body.ok).toBe(false);
      expect(res.body.error).toContain("Confidence");
    });

    test("validates decision value", async () => {
      const token = makeToken(["ai:decisions:write"]);

      const invalidDecision = {
        organizationId: "org-123",
        invoiceId: "invoice-123",
        agent: "billing_audit",
        decision: "invalid",
        confidence: 0.95,
        rationale: {},
      };

      const res = await request(app)
        .post("/api/ai-decisions")
        .set("Authorization", authHeader(token))
        .send(invalidDecision);

      expect(res.status).toBe(400);
      expect(res.body.ok).toBe(false);
      expect(res.body.error).toContain("Decision");
    });

    test("requires all required fields", async () => {
      const token = makeToken(["ai:decisions:write"]);

      const res = await request(app)
        .post("/api/ai-decisions")
        .set("Authorization", authHeader(token))
        .send({});

      expect(res.status).toBe(400);
    });

    test("requires authentication", async () => {
      const res = await request(app).post("/api/ai-decisions").send({});

      expect(res.status).toBe(401);
    });

    test("requires correct scope", async () => {
      const token = makeToken(["ai:decisions:read"]);

      const res = await request(app)
        .post("/api/ai-decisions")
        .set("Authorization", authHeader(token))
        .send({});

      expect(res.status).toBe(403);
    });
  });

  describe("POST /api/ai-decisions/:id/feedback", () => {
    test("creates feedback for a decision", async () => {
      prisma.aiDecision.findUnique.mockResolvedValue(mockDecision);
      prisma.aiFeedback.create.mockResolvedValue(mockFeedback);
      const token = makeToken(["ai:decisions:write"]);

      const feedbackData = {
        outcome: "correct",
        notes: "Decision was accurate",
      };

      const res = await request(app)
        .post("/api/ai-decisions/decision-123/feedback")
        .set("Authorization", authHeader(token))
        .send(feedbackData);

      expect(res.status).toBe(201);
      expect(res.body.ok).toBe(true);
      expect(res.body.feedback).toMatchObject({
        outcome: feedbackData.outcome,
        notes: feedbackData.notes,
      });
      expect(prisma.aiFeedback.create).toHaveBeenCalledWith({
        data: {
          aiDecisionId: "decision-123",
          outcome: feedbackData.outcome,
          notes: feedbackData.notes,
        },
      });
    });

    test("validates outcome value", async () => {
      prisma.aiDecision.findUnique.mockResolvedValue(mockDecision);
      const token = makeToken(["ai:decisions:write"]);

      const invalidFeedback = {
        outcome: "invalid",
        notes: "Some notes",
      };

      const res = await request(app)
        .post("/api/ai-decisions/decision-123/feedback")
        .set("Authorization", authHeader(token))
        .send(invalidFeedback);

      expect(res.status).toBe(400);
      expect(res.body.ok).toBe(false);
      expect(res.body.error).toContain("Outcome");
    });

    test("returns 404 for non-existent decision", async () => {
      prisma.aiDecision.findUnique.mockResolvedValue(null);
      const token = makeToken(["ai:decisions:write"]);

      const feedbackData = {
        outcome: "correct",
        notes: "Decision was accurate",
      };

      const res = await request(app)
        .post("/api/ai-decisions/nonexistent/feedback")
        .set("Authorization", authHeader(token))
        .send(feedbackData);

      expect(res.status).toBe(404);
      expect(res.body.error).toBe("AI decision not found");
    });

    test("returns 409 if feedback already exists", async () => {
      prisma.aiDecision.findUnique.mockResolvedValue(mockDecisionWithFeedback);
      const token = makeToken(["ai:decisions:write"]);

      const feedbackData = {
        outcome: "correct",
        notes: "Decision was accurate",
      };

      const res = await request(app)
        .post("/api/ai-decisions/decision-123/feedback")
        .set("Authorization", authHeader(token))
        .send(feedbackData);

      expect(res.status).toBe(409);
      expect(res.body.error).toContain("already exists");
    });

    test("requires authentication", async () => {
      const res = await request(app)
        .post("/api/ai-decisions/decision-123/feedback")
        .send({ outcome: "correct" });

      expect(res.status).toBe(401);
    });
  });

  describe("PATCH /api/ai-feedback/:id", () => {
    test("updates feedback successfully", async () => {
      const updatedFeedback = {
        ...mockFeedback,
        outcome: "false_positive",
        notes: "Updated notes",
      };
      prisma.aiFeedback.update.mockResolvedValue(updatedFeedback);
      const token = makeToken(["ai:decisions:write"]);

      const updateData = {
        outcome: "false_positive",
        notes: "Updated notes",
      };

      const res = await request(app)
        .patch("/api/ai-feedback/feedback-123")
        .set("Authorization", authHeader(token))
        .send(updateData);

      expect(res.status).toBe(200);
      expect(res.body.ok).toBe(true);
      expect(res.body.feedback.outcome).toBe("false_positive");
      expect(res.body.feedback.notes).toBe("Updated notes");
    });

    test("validates outcome value if provided", async () => {
      const token = makeToken(["ai:decisions:write"]);

      const invalidUpdate = {
        outcome: "invalid",
      };

      const res = await request(app)
        .patch("/api/ai-feedback/feedback-123")
        .set("Authorization", authHeader(token))
        .send(invalidUpdate);

      expect(res.status).toBe(400);
      expect(res.body.ok).toBe(false);
      expect(res.body.error).toContain("Outcome");
    });

    test("returns 404 for non-existent feedback", async () => {
      prisma.aiFeedback.update.mockRejectedValue({ code: "P2025" });
      const token = makeToken(["ai:decisions:write"]);

      const res = await request(app)
        .patch("/api/ai-feedback/nonexistent")
        .set("Authorization", authHeader(token))
        .send({ outcome: "correct" });

      expect(res.status).toBe(404);
      expect(res.body.error).toBe("Feedback not found");
    });

    test("requires authentication", async () => {
      const res = await request(app)
        .patch("/api/ai-feedback/feedback-123")
        .send({ outcome: "correct" });

      expect(res.status).toBe(401);
    });
  });

  describe("GET /api/ai-decisions/:id/feedback", () => {
    test("returns feedback for a decision", async () => {
      const feedbackWithDecision = {
        ...mockFeedback,
        aiDecision: mockDecision,
      };
      prisma.aiFeedback.findUnique.mockResolvedValue(feedbackWithDecision);
      const token = makeToken(["ai:decisions:read"]);

      const res = await request(app)
        .get("/api/ai-decisions/decision-123/feedback")
        .set("Authorization", authHeader(token));

      expect(res.status).toBe(200);
      expect(res.body.ok).toBe(true);
      expect(res.body.feedback).toBeDefined();
      expect(res.body.feedback.aiDecision).toBeDefined();
      expect(prisma.aiFeedback.findUnique).toHaveBeenCalledWith({
        where: { aiDecisionId: "decision-123" },
        include: { aiDecision: true },
      });
    });

    test("returns 404 if feedback not found", async () => {
      prisma.aiFeedback.findUnique.mockResolvedValue(null);
      const token = makeToken(["ai:decisions:read"]);

      const res = await request(app)
        .get("/api/ai-decisions/decision-123/feedback")
        .set("Authorization", authHeader(token));

      expect(res.status).toBe(404);
      expect(res.body.error).toBe("Feedback not found");
    });

    test("requires authentication", async () => {
      const res = await request(app).get(
        "/api/ai-decisions/decision-123/feedback",
      );

      expect(res.status).toBe(401);
    });
  });
});

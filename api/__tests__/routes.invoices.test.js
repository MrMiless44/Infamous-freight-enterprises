const request = require("supertest");
const jwt = require("jsonwebtoken");

jest.mock("../src/db/prisma", () => ({
  prisma: {
    invoice: {
      create: jest.fn(),
      findMany: jest.fn(),
      findUnique: jest.fn(),
      update: jest.fn(),
    },
  },
}));

jest.mock("../src/services/aiSyntheticClient", () => ({
  sendCommand: jest.fn(),
}));

const { prisma } = require("../src/db/prisma");
const { sendCommand } = require("../src/services/aiSyntheticClient");
const app = require("../src/server");

const skipOnNode22 = global.skipSupertestOnNode22 ? describe.skip : describe;

const makeToken = (scopes) =>
  jwt.sign(
    {
      sub: "test-user",
      scopes,
    },
    process.env.JWT_SECRET,
  );

const authHeader = (token) => `Bearer ${token}`;

skipOnNode22("Invoice routes", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test("creates a new invoice with defaults", async () => {
    const token = makeToken(["billing:write"]);
    const createdInvoice = {
      id: "inv-1",
      carrier: "Blue Steel Logistics",
      reference: "INV-1001",
      totalAmount: 1200,
      currency: "USD",
      auditResult: null,
      savings: 0,
      status: "pending",
    };
    prisma.invoice.create.mockResolvedValueOnce(createdInvoice);

    const res = await request(app)
      .post("/api/invoices")
      .set("Authorization", authHeader(token))
      .send({
        carrier: "Blue Steel Logistics",
        reference: "INV-1001",
        totalAmount: 1200,
      });

    expect(res.status).toBe(201);
    expect(res.body.ok).toBe(true);
    expect(res.body.invoice).toEqual(createdInvoice);
    expect(prisma.invoice.create).toHaveBeenCalledWith({
      data: expect.objectContaining({
        carrier: "Blue Steel Logistics",
        reference: "INV-1001",
        totalAmount: 1200,
        currency: "USD",
        status: "pending",
      }),
    });
  });

  test("returns conflict when reference already exists", async () => {
    const token = makeToken(["billing:write"]);
    prisma.invoice.create.mockRejectedValueOnce({ code: "P2002" });

    const res = await request(app)
      .post("/api/invoices")
      .set("Authorization", authHeader(token))
      .send({
        carrier: "Northern Freight",
        reference: "INV-1001",
        totalAmount: 500,
      });

    expect(res.status).toBe(409);
    expect(res.body.ok).toBeFalsy();
    expect(prisma.invoice.create).toHaveBeenCalled();
  });

  test("lists invoices ordered by newest first", async () => {
    const token = makeToken(["billing:read"]);
    const invoices = [
      {
        id: "inv-2",
        carrier: "Northern Freight",
        reference: "INV-1002",
        totalAmount: 845.75,
        currency: "USD",
        auditResult: null,
        savings: 0,
        status: "pending",
      },
    ];
    prisma.invoice.findMany.mockResolvedValueOnce(invoices);

    const res = await request(app)
      .get("/api/invoices")
      .set("Authorization", authHeader(token));

    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.invoices).toEqual(invoices);
    expect(prisma.invoice.findMany).toHaveBeenCalledWith({
      orderBy: { createdAt: "desc" },
    });
  });

  test("audits an invoice with AI and updates status", async () => {
    const token = makeToken(["billing:read", "ai:command"]);
    const invoice = {
      id: "inv-3",
      carrier: "Quantum Haulage",
      reference: "INV-1003",
      totalAmount: 2230.0,
      currency: "USD",
      status: "pending",
    };
    prisma.invoice.findUnique.mockResolvedValueOnce(invoice);
    sendCommand.mockResolvedValueOnce({ decision: "approve", savings: 150.25 });
    const updatedInvoice = { ...invoice, status: "approved", savings: 150.25 };
    prisma.invoice.update.mockResolvedValueOnce(updatedInvoice);

    const res = await request(app)
      .post(`/api/invoices/${invoice.id}/audit`)
      .set("Authorization", authHeader(token))
      .send();

    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.invoice).toEqual(updatedInvoice);
    expect(sendCommand).toHaveBeenCalledWith(
      "audit_invoice",
      {
        invoice: {
          carrier: invoice.carrier,
          reference: invoice.reference,
          totalAmount: invoice.totalAmount,
          currency: invoice.currency,
        },
        ruleset: "standard_freight",
      },
      { user: "test-user" },
    );
    expect(prisma.invoice.update).toHaveBeenCalledWith({
      where: { id: invoice.id },
      data: expect.objectContaining({
        auditResult: { decision: "approve", savings: 150.25 },
        savings: 150.25,
        status: "approved",
      }),
    });
  });

  test("returns 404 when invoice is missing during audit", async () => {
    const token = makeToken(["billing:read", "ai:command"]);
    prisma.invoice.findUnique.mockResolvedValueOnce(null);

    const res = await request(app)
      .post("/api/invoices/missing/audit")
      .set("Authorization", authHeader(token))
      .send();

    expect(res.status).toBe(404);
    expect(res.body.ok).toBe(false);
    expect(prisma.invoice.update).not.toHaveBeenCalled();
  });
});

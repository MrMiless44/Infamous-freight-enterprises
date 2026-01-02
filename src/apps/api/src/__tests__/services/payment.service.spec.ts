import { PrismaClient } from "@prisma/client";
import { PaymentService } from "../../services/paymentService";
import Stripe from "stripe";

jest.mock("@prisma/client");
jest.mock("stripe");

describe("PaymentService", () => {
  let paymentService: PaymentService;
  let prisma: PrismaClient;
  let stripe: Stripe;

  beforeEach(() => {
    jest.clearAllMocks();
    prisma = new PrismaClient();
    stripe = new Stripe("sk_test_123", { apiVersion: "2024-06-20" });
    paymentService = new PaymentService(prisma, stripe);
  });

  describe("processPayment", () => {
    it("should process payment successfully", async () => {
      const paymentData = {
        amount: 5000,
        currency: "USD",
        stripeToken: "tok_visa",
        customerId: "cust-123",
        description: "Shipment #123",
      };

      const result = await paymentService.processPayment(paymentData);

      expect(result).toHaveProperty("transactionId");
      expect(result).toHaveProperty("status", "completed");
    });

    it("should handle payment failures", async () => {
      const paymentData = {
        amount: 5000,
        currency: "USD",
        stripeToken: "tok_chargeDeclined",
        customerId: "cust-123",
      };

      await expect(
        paymentService.processPayment(paymentData),
      ).rejects.toThrow();
    });

    it("should validate payment amount", async () => {
      const paymentData = {
        amount: -100,
        currency: "USD",
        stripeToken: "tok_visa",
        customerId: "cust-123",
      };

      await expect(
        paymentService.processPayment(paymentData),
      ).rejects.toThrow();
    });
  });

  describe("refundPayment", () => {
    it("should refund payment successfully", async () => {
      const result = await paymentService.refundPayment("ch_123", 5000);

      expect(result).toHaveProperty("refundId");
      expect(result).toHaveProperty("status", "succeeded");
    });

    it("should handle refund errors", async () => {
      await expect(
        paymentService.refundPayment("invalid_charge", 5000),
      ).rejects.toThrow();
    });
  });

  describe("createInvoice", () => {
    it("should create invoice", async () => {
      const invoiceData = {
        customerId: "cust-123",
        shipmentIds: ["ship-123", "ship-124"],
        dueDate: new Date("2026-02-15"),
      };

      const result = await paymentService.createInvoice(invoiceData);

      expect(result).toHaveProperty("invoiceNumber");
      expect(result).toHaveProperty("total");
    });
  });

  describe("subscriptionManagement", () => {
    it("should create subscription", async () => {
      const result = await paymentService.createSubscription(
        "cust-123",
        "prod_starter",
      );

      expect(result).toHaveProperty("subscriptionId");
    });

    it("should cancel subscription", async () => {
      const result = await paymentService.cancelSubscription("sub_123");

      expect(result).toHaveProperty("status", "canceled");
    });

    it("should update subscription", async () => {
      const result = await paymentService.updateSubscription("sub_123", {
        priceId: "price_professional",
      });

      expect(result).toHaveProperty("subscriptionId");
    });
  });
});

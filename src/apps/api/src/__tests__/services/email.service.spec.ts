import { EmailNotificationService } from "../../services/emailNotificationService";
import nodemailer from "nodemailer";

jest.mock("nodemailer");

describe("EmailNotificationService", () => {
  let emailService: EmailNotificationService;

  beforeEach(() => {
    jest.clearAllMocks();
    emailService = new EmailNotificationService();
  });

  describe("sendShipmentNotification", () => {
    it("should send shipment creation email", async () => {
      const result = await emailService.sendShipmentNotification(
        "cust-123",
        "ship-123",
        "created",
      );

      expect(result).toHaveProperty("messageId");
      expect(result).toHaveProperty("status", "sent");
    });

    it("should send delivery confirmation email", async () => {
      const result = await emailService.sendShipmentNotification(
        "cust-123",
        "ship-123",
        "delivered",
      );

      expect(result).toHaveProperty("status", "sent");
    });
  });

  describe("sendInvoiceEmail", () => {
    it("should send invoice to customer", async () => {
      const result = await emailService.sendInvoiceEmail(
        "customer@example.com",
        "inv-123",
        "https://example.com/invoice.pdf",
      );

      expect(result).toHaveProperty("messageId");
      expect(result).toHaveProperty("status", "sent");
    });

    it("should validate email address", async () => {
      await expect(
        emailService.sendInvoiceEmail(
          "invalid-email",
          "inv-123",
          "https://example.com/invoice.pdf",
        ),
      ).rejects.toThrow();
    });
  });

  describe("sendAlertEmail", () => {
    it("should send alert email", async () => {
      const result = await emailService.sendAlertEmail(
        "admin@example.com",
        "System Alert",
        "High CPU usage detected",
      );

      expect(result).toHaveProperty("status", "sent");
    });
  });

  describe("sendBulkEmail", () => {
    it("should send emails to multiple recipients", async () => {
      const recipients = [
        "user1@example.com",
        "user2@example.com",
        "user3@example.com",
      ];

      const result = await emailService.sendBulkEmail(
        recipients,
        "Maintenance Notice",
        "Scheduled maintenance tomorrow",
      );

      expect(result).toHaveProperty("successCount", 3);
      expect(result).toHaveProperty("failureCount", 0);
    });
  });

  describe("queueEmail", () => {
    it("should queue email for later delivery", async () => {
      const result = await emailService.queueEmail({
        to: "customer@example.com",
        subject: "Shipment Update",
        template: "shipment-update",
        data: { shipmentId: "ship-123" },
        sendAt: new Date(Date.now() + 3600000),
      });

      expect(result).toHaveProperty("queueId");
      expect(result).toHaveProperty("status", "queued");
    });
  });
});

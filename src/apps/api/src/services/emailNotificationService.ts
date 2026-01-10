import crypto from "crypto";

const isValidEmail = (email: string) =>
  /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

export class EmailNotificationService {
  async sendShipmentNotification(
    customerId: string,
    shipmentId: string,
    status: string,
  ) {
    if (!customerId || !shipmentId) {
      throw new Error("Missing shipment details");
    }
    return {
      messageId: crypto.randomUUID(),
      status: "sent",
      shipmentStatus: status,
    };
  }

  async sendInvoiceEmail(email: string, invoiceId: string, invoiceUrl: string) {
    if (!isValidEmail(email)) {
      throw new Error("Invalid email");
    }
    return {
      messageId: crypto.randomUUID(),
      status: "sent",
      invoiceId,
      invoiceUrl,
    };
  }

  async sendAlertEmail(to: string, subject: string, body: string) {
    if (!isValidEmail(to)) {
      throw new Error("Invalid email");
    }
    return {
      messageId: crypto.randomUUID(),
      status: "sent",
      subject,
      body,
    };
  }

  async sendBulkEmail(recipients: string[], subject: string, body: string) {
    const failures = recipients.filter((email) => !isValidEmail(email)).length;
    if (failures > 0) {
      throw new Error("Invalid recipients");
    }
    return {
      successCount: recipients.length,
      failureCount: 0,
      subject,
      body,
    };
  }

  async queueEmail(input: {
    to: string;
    subject: string;
    template: string;
    data?: Record<string, unknown>;
    sendAt?: Date;
  }) {
    if (!isValidEmail(input.to)) {
      throw new Error("Invalid email");
    }
    return {
      queueId: crypto.randomUUID(),
      status: "queued",
      sendAt: input.sendAt ?? new Date(),
    };
  }
}

export default EmailNotificationService;

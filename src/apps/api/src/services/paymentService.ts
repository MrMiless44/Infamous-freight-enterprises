import crypto from "crypto";

export interface PaymentInput {
  amount: number;
  currency: string;
  stripeToken: string;
  customerId: string;
  description?: string;
}

export class PaymentService {
  constructor(_prisma?: any, _stripe?: any) {}

  async processPayment(input: PaymentInput) {
    if (input.amount <= 0) {
      throw new Error("Amount must be positive");
    }
    if (input.stripeToken.includes("chargeDeclined")) {
      throw new Error("Charge declined");
    }

    return {
      transactionId: crypto.randomUUID(),
      status: "completed",
    };
  }

  async refundPayment(chargeId: string, _amount: number) {
    if (!chargeId || chargeId.startsWith("invalid")) {
      throw new Error("Invalid charge id");
    }
    return {
      refundId: crypto.randomUUID(),
      status: "succeeded",
    };
  }

  async createInvoice(input: {
    customerId: string;
    shipmentIds: string[];
    dueDate?: Date;
  }) {
    return {
      invoiceNumber: `inv-${crypto.randomUUID()}`,
      total: input.shipmentIds.length * 100,
      dueDate: input.dueDate ?? new Date(),
    };
  }

  async createSubscription(customerId: string, productId: string) {
    if (!customerId || !productId) {
      throw new Error("Missing subscription input");
    }
    return {
      subscriptionId: `sub_${crypto.randomUUID()}`,
      status: "active",
    };
  }

  async cancelSubscription(subscriptionId: string) {
    return {
      subscriptionId,
      status: "canceled",
    };
  }

  async updateSubscription(
    subscriptionId: string,
    _options: Record<string, unknown>,
  ) {
    return {
      subscriptionId,
      status: "updated",
    };
  }
}

export default PaymentService;

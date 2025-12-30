/**
 * Notification Service
 * Handles email, SMS, and push notifications
 */

import nodemailer from "nodemailer";
import { prisma } from "../lib/prisma";

interface NotificationOptions {
  email?: boolean;
  sms?: boolean;
  push?: boolean;
}

export class NotificationService {
  private static transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || "587"),
    secure: process.env.SMTP_SECURE === "true",
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASSWORD,
    },
  });

  /**
   * Send shipment update notification
   */
  static async notifyShipmentUpdate(
    shipment: any,
    options: NotificationOptions = { email: true, sms: true },
  ) {
    try {
      const customer = await prisma.customer.findUnique({
        where: { id: shipment.customerId },
      });

      if (!customer) return;

      const message = `Your shipment ${shipment.id} status has been updated to: ${shipment.status}`;

      if (options.email && customer.email) {
        await this.sendEmail(customer.email, "Shipment Update", message);
      }

      if (options.sms && customer.phone) {
        await this.sendSMS(customer.phone, message);
      }

      if (options.push) {
        await this.sendPushNotification(
          customer.id,
          "Shipment Update",
          message,
        );
      }

      // Store notification in database
      await prisma.notification.create({
        data: {
          title: "Shipment Update",
          message,
          customerId: customer.id,
          type: "shipment_update",
          data: { shipmentId: shipment.id },
        },
      });
    } catch (error) {
      console.error("Failed to send notification:", error);
    }
  }

  /**
   * Send email notification
   */
  static async sendEmail(
    to: string,
    subject: string,
    content: string,
  ): Promise<boolean> {
    try {
      await this.transporter.sendMail({
        from: process.env.SMTP_FROM || "noreply@infamousfreight.com",
        to,
        subject,
        html: this.formatEmailTemplate(subject, content),
      });
      return true;
    } catch (error) {
      console.error("Failed to send email:", error);
      return false;
    }
  }

  /**
   * Send SMS notification
   */
  static async sendSMS(phone: string, message: string): Promise<boolean> {
    try {
      // Implementation depends on SMS provider (Twilio, AWS SNS, etc.)
      // Example with Twilio (install twilio package first)
      // const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
      // await client.messages.create({
      //   body: message,
      //   from: process.env.TWILIO_PHONE_NUMBER,
      //   to: phone
      // });

      console.log(`SMS sent to ${phone}: ${message}`);
      return true;
    } catch (error) {
      console.error("Failed to send SMS:", error);
      return false;
    }
  }

  /**
   * Send push notification
   */
  static async sendPushNotification(
    userId: string,
    title: string,
    message: string,
  ): Promise<boolean> {
    try {
      // Implementation depends on push notification service
      // (Firebase Cloud Messaging, OneSignal, etc.)
      console.log(`Push notification to ${userId}: ${title} - ${message}`);
      return true;
    } catch (error) {
      console.error("Failed to send push notification:", error);
      return false;
    }
  }

  /**
   * Notify driver of new assignment
   */
  static async notifyDriverAssignment(driverId: string, shipmentId: string) {
    const message = `You have been assigned shipment ${shipmentId}`;
    const driver = await prisma.driverProfile.findUnique({
      where: { id: driverId },
      include: { user: true },
    });

    if (driver?.user?.email) {
      await this.sendEmail(
        driver.user.email,
        "New Shipment Assignment",
        message,
      );
    }
  }

  /**
   * Notify admin of issues
   */
  static async notifyAdminIssue(issue: {
    title: string;
    description: string;
    severity: "low" | "medium" | "high" | "critical";
  }) {
    const adminEmail = process.env.ADMIN_EMAIL || "admin@infamousfreight.com";
    const message = `[${issue.severity.toUpperCase()}] ${issue.title}\n\n${issue.description}`;
    await this.sendEmail(adminEmail, "System Alert", message);
  }

  /**
   * Format HTML email template
   */
  private static formatEmailTemplate(subject: string, content: string): string {
    return `
      <!DOCTYPE html>
      <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: #007bff; color: white; padding: 20px; border-radius: 5px 5px 0 0; }
            .body { background: #f9f9f9; padding: 20px; border: 1px solid #ddd; }
            .footer { background: #f1f1f1; padding: 10px; text-align: center; font-size: 12px; }
            .button { background: #007bff; color: white; padding: 10px 20px; border-radius: 5px; text-decoration: none; display: inline-block; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>${subject}</h1>
            </div>
            <div class="body">
              <p>${content}</p>
            </div>
            <div class="footer">
              <p>&copy; 2025 Infamous Freight Enterprises. All rights reserved.</p>
            </div>
          </div>
        </body>
      </html>
    `;
  }
}

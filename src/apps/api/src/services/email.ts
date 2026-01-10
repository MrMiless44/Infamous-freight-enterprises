import nodemailer from "nodemailer";
import config from "../config";

// Email templates for trial-to-paid conversion
const EMAIL_TEMPLATES = {
  trial_welcome: {
    subject: "Welcome to Infamous Freight! Your 30-day free trial starts now",
    title: "Let's Get Started with Infamous Freight",
    preview:
      "Your free trial includes full access to all features. Here's what you can do right now.",
    body: `
      <p>Hi {{firstName}},</p>
      <p>Welcome to Infamous Freight! We're excited to have you on board. Your 30-day free trial gives you full access to all {{tier}} features, no credit card required.</p>
      
      <h3>What You Can Do Now:</h3>
      <ul>
        <li>📍 Track all your shipments in real-time</li>
        <li>📊 Access advanced analytics and reporting</li>
        <li>🤖 Get AI-powered optimization recommendations</li>
        <li>👥 Invite your team members (plan dependent)</li>
      </ul>
      
      <p><a href="{{dashboardUrl}}">Start Your First Shipment →</a></p>
      
      <p>Questions? We're here to help! Reply to this email or visit our <a href="https://help.infamousfreight.com">help center</a>.</p>
      <p>- The Infamous Freight Team</p>
    `,
  },

  trial_feature_highlight: {
    subject: "Did you know? Here's how to save 30% on shipping costs",
    title: "Unlock Hidden Savings with AI Route Optimization",
    preview: "See how other customers reduced costs by using our AI features.",
    body: `
      <p>Hi {{firstName}},</p>
      <p>We wanted to show you something powerful. One of our most popular {{tier}} features is AI route optimization.</p>
      
      <h3>Real Customer Results:</h3>
      <blockquote>
        <strong>"We saved 28% on fuel costs in the first month using Infamous Freight's route optimization."</strong>
        <br/>- John Smith, Fleet Manager at ABC Logistics
      </blockquote>
      
      <p><a href="{{dashboardUrl}}/optimization">Try Route Optimization →</a></p>
      
      <p>This feature alone has paid for annual plans in as little as 3 months for many customers. Your trial includes full access!</p>
      <p>- The Infamous Freight Team</p>
    `,
  },

  trial_engagement: {
    subject: "We noticed you haven't set up a shipment yet — Here's how (2 min)",
    title: "Getting Started is Easy",
    preview: "Quick guide to set up your first shipment and see the platform in action.",
    body: `
      <p>Hi {{firstName}},</p>
      <p>We noticed you haven't created a shipment yet. Let us show you how easy it is!</p>
      
      <h3>3-Step Setup (5 minutes):</h3>
      <ol>
        <li><strong>Enter Origin & Destination</strong> - Where are you shipping from and to?</li>
        <li><strong>Add Shipment Details</strong> - Weight, dimensions, cargo type</li>
        <li><strong>Get Optimization</strong> - Our AI suggests the best route & carrier</li>
      </ol>
      
      <p><a href="{{dashboardUrl}}/new-shipment">Create Your First Shipment →</a></p>
      
      <p>We'll show you how much you could save, and you'll see real-time tracking in action.</p>
      <p>- The Infamous Freight Team</p>
    `,
  },

  trial_midpoint_checkpoint: {
    subject: "Midway through your trial! Here's what you're using most",
    title: "Your Infamous Freight Progress",
    preview: "You've unlocked {{featureCount}} features. See what's working best for you.",
    body: `
      <p>Hi {{firstName}},</p>
      <p>You're halfway through your trial! Here's what you've been using:</p>
      
      <h3>Your Usage So Far:</h3>
      <ul>
        <li>✓ {{shipmentsTracked}} shipments tracked</li>
        <li>✓ {{estimatedSavings}} estimated in cost savings</li>
        <li>✓ {{optimizationsRun}} optimization runs</li>
        <li>✓ {{teamMembers}} team members invited</li>
      </ul>
      
      <p>You still have <strong>16 days</strong> left to explore everything. Here are some features you might not have tried yet:</p>
      <ul>
        <li>📱 Mobile app for on-the-go tracking</li>
        <li>🔔 Smart notifications for important updates</li>
        <li>📈 Advanced reporting & analytics</li>
        <li>🔌 API access for custom integrations</li>
      </ul>
      
      <p><a href="{{dashboardUrl}}/features">Explore More Features →</a></p>
      
      <p>Questions? Our support team is here to help.</p>
      <p>- The Infamous Freight Team</p>
    `,
  },

  trial_upgrade_offer_early: {
    subject: "Special offer: {{discountPercent}}% off your first {{months}} months",
    title: "Exclusive Early-Bird Pricing",
    preview:
      "Lock in {{discountPercent}}% savings when you upgrade now. Offer expires in 5 days.",
    body: `
      <p>Hi {{firstName}},</p>
      <p>You're getting great results with Infamous Freight. As a thank you, we'd like to offer you an exclusive deal:</p>
      
      <h3>Early-Bird Special:</h3>
      <p><strong>{{discountPercent}}% off</strong> your first {{months}} months of {{tier}}</p>
      <p>That's just <strong>{{discountedPrice}}/month</strong> instead of {{regularPrice}} — locked in for life when you upgrade today!</p>
      
      <p><a href="{{upgradeUrl}}" style="display: inline-block; background: #3b82f6; color: white; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: bold;">Upgrade Now & Save {{discountPercent}}%</a></p>
      
      <p style="font-size: 12px; color: #666;">Offer expires in 5 days. After your {{months}}-month discount period, your plan continues at {{regularPrice}}/month. Cancel anytime.</p>
      
      <p>- The Infamous Freight Team</p>
    `,
  },

  trial_final_offer: {
    subject: "Last day of your trial! Final offer: 60 days free when you upgrade",
    title: "Don't Miss Out — Final Offer Inside",
    preview: "Get 2 months free when you upgrade in the next 24 hours.",
    body: `
      <p>Hi {{firstName}},</p>
      <p>Your trial expires tomorrow. Before it goes, we want to make you an offer you can't refuse:</p>
      
      <h3>Last-Chance Offer:</h3>
      <p><strong>Upgrade today, get 60 days FREE.</strong></p>
      <p>That means full access to all {{tier}} features for 2 months on us. You'd save {{freeSavings}} in value!</p>
      
      <p style="background: #fef3c7; border-left: 4px solid #f59e0b; padding: 15px; margin: 20px 0;">
        <strong>⚠️ This offer expires in 24 hours.</strong> Your trial ends tomorrow and you'll lose access to all your data.
      </p>
      
      <p><a href="{{upgradeUrl}}" style="display: inline-block; background: #10b981; color: white; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: bold;">Upgrade Now & Get 60 Days Free</a></p>
      
      <p>Or explore our pricing options:</p>
      <ul>
        <li><a href="{{pricingUrl}}">View All Plans</a></li>
        <li><a href="{{contactUrl}}">Talk to Sales</a></li>
      </ul>
      
      <p>- The Infamous Freight Team</p>
    `,
  },

  payment_succeeded: {
    subject: "Welcome {{firstName}}! Your Infamous Freight subscription is active",
    title: "Your Subscription is Active",
    preview: "You're all set! Here's what's next.",
    body: `
      <p>Hi {{firstName}},</p>
      <p>Welcome to Infamous Freight! Your {{tier}} subscription is now active.</p>
      
      <h3>What's Next:</h3>
      <ul>
        <li>✓ Subscription active: {{planName}}</li>
        <li>✓ Next billing date: {{nextBillingDate}}</li>
        <li>✓ Amount: {{amount}}</li>
      </ul>
      
      <p><a href="{{dashboardUrl}}">Go to Dashboard</a></p>
      
      <h3>Congratulations on Getting Started!</h3>
      <p>You're now part of a community of thousands of freight companies using Infamous Freight to optimize their operations. Here are some next steps:</p>
      
      <ol>
        <li>Set up your team (max {{maxTeamMembers}} members on {{tier}})</li>
        <li>Configure your carriers and warehouses</li>
        <li>Create your first automated workflow</li>
        <li>Schedule your onboarding call with our success team</li>
      </ol>
      
      <p><a href="{{onboardingUrl}}">Schedule Onboarding Call</a></p>
      
      <p>Questions or need help? Reply to this email or visit our <a href="https://help.infamousfreight.com">help center</a>.</p>
      <p>- The Infamous Freight Team</p>
    `,
  },

  churn_prevention: {
    subject: "{{firstName}}, we noticed you haven't used Infamous Freight in {{days}} days",
    title: "We Miss You!",
    preview: "Let us help you get the most out of your subscription.",
    body: `
      <p>Hi {{firstName}},</p>
      <p>We noticed you haven't logged in to Infamous Freight in {{days}} days. We'd love to help you get the most out of your {{tier}} subscription.</p>
      
      <p>Are you facing any challenges? Here are some common ways we can help:</p>
      <ul>
        <li>📞 Need onboarding help? <a href="{{onboardingUrl}}">Schedule a call</a></li>
        <li>❓ Have questions? <a href="{{supportUrl}}">Contact support</a></li>
        <li>🚀 Want to see advanced features? <a href="{{tutorialsUrl}}">Watch video tutorials</a></li>
      </ul>
      
      <p><a href="{{dashboardUrl}}">Log In & Get Started</a></p>
      
      <p>Or let us know if there's anything we can do to improve your experience. We offer refunds within 30 days if the service isn't right for you.</p>
      <p>- The Infamous Freight Team</p>
    `,
  },
};

interface EmailContext {
  [key: string]: string | number;
}

export class EmailService {
  private transporter: any;

  constructor() {
    const emailConfig = config.getEmailConfig();

    if (emailConfig.enabled) {
      this.transporter = nodemailer.createTransport({
        host: emailConfig.host,
        port: emailConfig.port,
        secure: emailConfig.secure, // true for 465, false for other ports
        auth: {
          user: emailConfig.user,
          pass: emailConfig.password,
        },
      });
    }
  }

  /**
   * Send trial welcome email (Day 0)
   */
  async sendTrialWelcome(email: string, context: EmailContext) {
    return this.sendEmail(
      email,
      EMAIL_TEMPLATES.trial_welcome,
      context,
      "trial_welcome"
    );
  }

  /**
   * Send feature highlight email (Day 3)
   */
  async sendFeatureHighlight(email: string, context: EmailContext) {
    return this.sendEmail(
      email,
      EMAIL_TEMPLATES.trial_feature_highlight,
      context,
      "trial_feature_highlight"
    );
  }

  /**
   * Send engagement email (Day 7)
   */
  async sendEngagementEmail(email: string, context: EmailContext) {
    return this.sendEmail(
      email,
      EMAIL_TEMPLATES.trial_engagement,
      context,
      "trial_engagement"
    );
  }

  /**
   * Send mid-trial checkpoint (Day 14)
   */
  async sendMidTrialCheckpoint(email: string, context: EmailContext) {
    return this.sendEmail(
      email,
      EMAIL_TEMPLATES.trial_midpoint_checkpoint,
      context,
      "trial_midpoint_checkpoint"
    );
  }

  /**
   * Send early upgrade offer (Day 21)
   */
  async sendUpgradeOfferEarly(email: string, context: EmailContext) {
    return this.sendEmail(
      email,
      EMAIL_TEMPLATES.trial_upgrade_offer_early,
      context,
      "trial_upgrade_offer_early"
    );
  }

  /**
   * Send final offer (Day 29)
   */
  async sendFinalOffer(email: string, context: EmailContext) {
    return this.sendEmail(
      email,
      EMAIL_TEMPLATES.trial_final_offer,
      context,
      "trial_final_offer"
    );
  }

  /**
   * Send payment success email
   */
  async sendPaymentSuccess(email: string, context: EmailContext) {
    return this.sendEmail(
      email,
      EMAIL_TEMPLATES.payment_succeeded,
      context,
      "payment_succeeded"
    );
  }

  /**
   * Send churn prevention email (when inactive for {{days}} days)
   */
  async sendChurnPrevention(email: string, context: EmailContext) {
    return this.sendEmail(
      email,
      EMAIL_TEMPLATES.churn_prevention,
      context,
      "churn_prevention"
    );
  }

  /**
   * Core email sending logic with template rendering
   */
  private async sendEmail(
    to: string,
    template: any,
    context: EmailContext,
    templateId: string
  ) {
    if (!this.transporter) {
      console.warn("Email service not configured. Skipping email:", templateId);
      return { success: false, error: "Email service not configured" };
    }

    try {
      // Render template with context
      const subject = this.renderTemplate(template.subject, context);
      const htmlContent = this.renderTemplate(template.body, context);

      // Send email
      const info = await this.transporter.sendMail({
        from: `Infamous Freight <${process.env.SMTP_FROM || "noreply@infamousfreight.com"}>`,
        to,
        subject,
        html: this.wrapHtml(htmlContent),
      });

      console.info(`Email sent: ${templateId} to ${to}`, { messageId: info.messageId });

      return {
        success: true,
        messageId: info.messageId,
      };
    } catch (error) {
      console.error(`Failed to send email: ${templateId}`, error);
      return {
        success: false,
        error: error instanceof Error ? error.message : "Unknown error",
      };
    }
  }

  /**
   * Render template with context variables ({{variable}} -> value)
   */
  private renderTemplate(template: string, context: EmailContext): string {
    return template.replace(/\{\{(\w+)\}\}/g, (match, key) => {
      return String(context[key] || match);
    });
  }

  /**
   * Wrap email content in HTML structure
   */
  private wrapHtml(content: string): string {
    return `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            h2, h3 { color: #1a1a1a; }
            a { color: #3b82f6; text-decoration: none; }
            a:hover { text-decoration: underline; }
            ul, ol { margin: 15px 0; padding-left: 20px; }
            blockquote { border-left: 4px solid #3b82f6; padding-left: 15px; margin-left: 0; color: #666; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .footer { font-size: 12px; color: #999; text-align: center; border-top: 1px solid #eee; padding-top: 20px; margin-top: 30px; }
          </style>
        </head>
        <body>
          <div class="container">
            ${content}
            <div class="footer">
              <p>© 2026 Infamous Freight Enterprises. All rights reserved.</p>
              <p>
                <a href="https://infamousfreight.com">Website</a> |
                <a href="https://help.infamousfreight.com">Help Center</a> |
                <a href="{{unsubscribeUrl}}">Unsubscribe</a>
              </p>
            </div>
          </div>
        </body>
      </html>
    `;
  }
}

export const emailService = new EmailService();

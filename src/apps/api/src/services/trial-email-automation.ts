import cron from "node-cron";
import prisma from "../lib/prismaClient";
import { emailService } from "../services/email";

// Email schedule (days into trial)
const EMAIL_SCHEDULE = {
  0: "sendTrialWelcome",
  3: "sendFeatureHighlight",
  7: "sendEngagementEmail",
  14: "sendMidTrialCheckpoint",
  21: "sendUpgradeOfferEarly",
  29: "sendFinalOffer",
};

// Churn prevention (inactive for days)
const CHURN_CHECK_DAYS = 7;

/**
 * Initialize trial-to-paid email automation
 * Runs daily to check which emails need to be sent
 */
export function initializeTrialEmailAutomation() {
  // Run every day at 2 AM
  cron.schedule("0 2 * * *", async () => {
    console.info("🔔 Running trial email automation...");

    try {
      // Get all active trials
      const activeTrials = await prisma.subscription.findMany({
        where: {
          isOnTrial: true,
          status: "active",
        },
        include: {
          organization: {
            include: {
              users: {
                select: { email: true, firstName: true },
                take: 1, // Get admin/first user
              },
            },
          },
        },
      });

      for (const subscription of activeTrials) {
        const user = subscription.organization.users[0];
        if (!user) continue;

        const daysSinceTrial = Math.floor(
          (Date.now() - subscription.createdAt.getTime()) /
            (24 * 60 * 60 * 1000),
        );

        // Check if it's time to send an email
        const emailMethod =
          EMAIL_SCHEDULE[daysSinceTrial as keyof typeof EMAIL_SCHEDULE];

        if (emailMethod) {
          const method = emailService[emailMethod as keyof typeof emailService];

          if (typeof method === "function") {
            const context = {
              firstName: user.firstName || "there",
              tier: subscription.tier,
              dashboardUrl: `${process.env.WEB_URL}/dashboard`,
              pricingUrl: `${process.env.WEB_URL}/pricing`,
              upgradeUrl: `${process.env.WEB_URL}/billing/upgrade?tier=${subscription.tier}`,
              contactUrl: `${process.env.WEB_URL}/contact-sales`,
              featureCount: 8,
              shipmentsTracked: 42,
              estimatedSavings: 3500,
              optimizationsRun: 12,
              teamMembers: 3,
              discountPercent: 25,
              months: 3,
              discountedPrice: "$749",
              regularPrice: "$999",
              freeSavings: "$1,998",
              planName: subscription.tier.toUpperCase(),
              nextBillingDate: new Date(
                subscription.currentPeriodEnd,
              ).toLocaleDateString(),
              amount: `$${subscription.priceMonthly}`,
              maxTeamMembers:
                subscription.tier === "professional" ? 10 : "unlimited",
              onboardingUrl: `${process.env.WEB_URL}/onboarding`,
              supportUrl: `https://help.infamousfreight.com`,
              tutorialsUrl: `${process.env.WEB_URL}/tutorials`,
              unsubscribeUrl: `${process.env.WEB_URL}/unsubscribe`,
            };

            await (method as Function).call(emailService, user.email, context);
          }
        }
      }

      // Check for inactive customers (churn prevention)
      await checkAndSendChurnPrevention();

      console.info("✅ Trial email automation complete");
    } catch (error) {
      console.error("Trial email automation failed:", error);
    }
  });
}

/**
 * Check for inactive customers and send churn prevention emails
 */
async function checkAndSendChurnPrevention() {
  try {
    const inactiveThreshold = new Date(
      Date.now() - CHURN_CHECK_DAYS * 24 * 60 * 60 * 1000,
    );

    const inactiveSubscriptions = await prisma.subscription.findMany({
      where: {
        status: "active",
        isOnTrial: false, // Only check paid subscriptions
      },
      include: {
        organization: {
          include: {
            users: {
              select: { email: true, firstName: true },
              take: 1,
            },
          },
        },
        revenueEvents: {
          where: {
            createdAt: { gte: inactiveThreshold },
          },
        },
      },
    });

    for (const subscription of inactiveSubscriptions) {
      // If no activity in last 7 days
      if (subscription.revenueEvents.length === 0) {
        const user = subscription.organization.users[0];
        if (!user) continue;

        const context = {
          firstName: user.firstName || "there",
          days: CHURN_CHECK_DAYS,
          tier: subscription.tier,
          dashboardUrl: `${process.env.WEB_URL}/dashboard`,
          onboardingUrl: `${process.env.WEB_URL}/onboarding`,
          supportUrl: `https://help.infamousfreight.com`,
          tutorialsUrl: `${process.env.WEB_URL}/tutorials`,
          unsubscribeUrl: `${process.env.WEB_URL}/unsubscribe`,
        };

        await emailService.sendChurnPrevention(user.email, context);

        // Log churn prevention event
        await prisma.revenueEvent.create({
          data: {
            subscriptionId: subscription.id,
            organizationId: subscription.organizationId,
            eventType: "churn_prevention_sent",
            description: `Churn prevention email sent - inactive for ${CHURN_CHECK_DAYS} days`,
          },
        });
      }
    }
  } catch (error) {
    console.error("Churn prevention check failed:", error);
  }
}

/**
 * Manually trigger trial-to-paid sequence for specific subscription
 * Useful for testing or re-sending emails
 */
export async function triggerTrialEmailSequence(
  subscriptionId: string,
  daysSinceTrial: number,
) {
  try {
    const subscription = await prisma.subscription.findUnique({
      where: { id: subscriptionId },
      include: {
        organization: {
          include: {
            users: {
              select: { email: true, firstName: true },
              take: 1,
            },
          },
        },
      },
    });

    if (!subscription || !subscription.organization.users[0]) {
      throw new Error("Subscription or user not found");
    }

    const user = subscription.organization.users[0];
    const emailMethod =
      EMAIL_SCHEDULE[daysSinceTrial as keyof typeof EMAIL_SCHEDULE];

    if (!emailMethod) {
      throw new Error(`No email configured for day ${daysSinceTrial}`);
    }

    const method = emailService[emailMethod as keyof typeof emailService];

    if (typeof method !== "function") {
      throw new Error(`Email method ${emailMethod} not found`);
    }

    const context = {
      firstName: user.firstName || "there",
      tier: subscription.tier,
      dashboardUrl: `${process.env.WEB_URL}/dashboard`,
      pricingUrl: `${process.env.WEB_URL}/pricing`,
      upgradeUrl: `${process.env.WEB_URL}/billing/upgrade?tier=${subscription.tier}`,
      contactUrl: `${process.env.WEB_URL}/contact-sales`,
      featureCount: 8,
      shipmentsTracked: 42,
      estimatedSavings: 3500,
      optimizationsRun: 12,
      teamMembers: 3,
      discountPercent: 25,
      months: 3,
      discountedPrice: "$749",
      regularPrice: "$999",
      freeSavings: "$1,998",
      planName: subscription.tier.toUpperCase(),
      nextBillingDate: new Date(
        subscription.currentPeriodEnd,
      ).toLocaleDateString(),
      amount: `$${subscription.priceMonthly}`,
      maxTeamMembers: subscription.tier === "professional" ? 10 : "unlimited",
      onboardingUrl: `${process.env.WEB_URL}/onboarding`,
      supportUrl: `https://help.infamousfreight.com`,
      tutorialsUrl: `${process.env.WEB_URL}/tutorials`,
      unsubscribeUrl: `${process.env.WEB_URL}/unsubscribe`,
    };

    await (method as Function).call(emailService, user.email, context);

    // Log manual trigger
    await prisma.revenueEvent.create({
      data: {
        subscriptionId: subscription.id,
        organizationId: subscription.organizationId,
        eventType: "email_triggered_manually",
        description: `${emailMethod} triggered manually for day ${daysSinceTrial}`,
      },
    });

    return { success: true, email: user.email, method: emailMethod };
  } catch (error) {
    console.error("Failed to trigger email sequence:", error);
    throw error;
  }
}

/**
 * Get email campaign statistics
 */
export async function getEmailCampaignStats() {
  try {
    const totalTrials = await prisma.subscription.count({
      where: { isOnTrial: true },
    });

    const convertedToPayment = await prisma.subscription.count({
      where: { isOnTrial: false },
    });

    const conversionRate =
      totalTrials > 0
        ? ((convertedToPayment / totalTrials) * 100).toFixed(2)
        : "0";

    const emailStats = await prisma.revenueEvent.groupBy({
      by: ["eventType"],
      where: {
        eventType: {
          in: [
            "trial_welcome_sent",
            "email_triggered_manually",
            "churn_prevention_sent",
            "payment_succeeded",
          ],
        },
      },
      _count: {
        id: true,
      },
    });

    return {
      totalTrials,
      convertedToPayment,
      conversionRatePercent: conversionRate,
      emailStats,
    };
  } catch (error) {
    console.error("Failed to get email campaign stats:", error);
    throw error;
  }
}

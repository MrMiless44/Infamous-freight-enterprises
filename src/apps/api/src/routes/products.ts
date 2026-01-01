/**
 * Enhanced Billing Routes with Stripe Products
 * Includes product catalog, pricing, and checkout endpoints
 */

import { Router, Request, Response, NextFunction } from "express";
import Stripe from "stripe";
import { requireAuth, requireScope } from "../middleware/auth";
import {
  validateRequestBody,
  handleValidationErrors,
} from "../middleware/validation";
import StripeProductsManager from "../lib/stripeProductsManager";
import {
  INFAMOUS_FREIGHT_PRODUCTS,
  getProductsByCategory,
} from "../lib/products";

const stripeApiVersion = "2024-06-20" as Stripe.LatestApiVersion;

// Initialize router
export const enhancedBillingRouter = Router();

// Middleware
enhancedBillingRouter.use(requireAuth);

// Initialize Stripe
function getStripeClient(): Stripe {
  const stripeKey = process.env.STRIPE_SECRET_KEY;
  if (!stripeKey) {
    throw new Error("STRIPE_SECRET_KEY not configured");
  }
  return new Stripe(stripeKey, { apiVersion: stripeApiVersion });
}

function getProductManager(): StripeProductsManager {
  const stripeKey = process.env.STRIPE_SECRET_KEY;
  if (!stripeKey) {
    throw new Error("STRIPE_SECRET_KEY not configured");
  }
  return new StripeProductsManager(stripeKey);
}

// ============================================================================
// PRODUCT CATALOG ENDPOINTS
// ============================================================================

/**
 * GET /billing/products
 * Get all products or filter by category
 */
enhancedBillingRouter.get(
  "/products",
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { category } = req.query;

      let products: any;
      if (category && typeof category === "string") {
        products = getProductsByCategory(category);
      } else {
        products = Object.values(INFAMOUS_FREIGHT_PRODUCTS).reduce(
          (acc, cat) => ({ ...acc, ...cat }),
          {},
        );
      }

      const formattedProducts = Object.entries(products).map(
        ([key, prod]: any) => ({
          id: prod.id,
          name: prod.name,
          description: prod.description,
          category: prod.category,
          prices: prod.prices,
          metadata: prod.metadata,
        }),
      );

      res.json({
        success: true,
        data: {
          products: formattedProducts,
          total: formattedProducts.length,
          category: category || "all",
        },
      });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * GET /billing/products/:productId
 * Get detailed product information
 */
enhancedBillingRouter.get(
  "/products/:productId",
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { productId } = req.params;

      // Find product in our catalog
      let foundProduct: any = null;
      for (const category of Object.values(INFAMOUS_FREIGHT_PRODUCTS)) {
        for (const product of Object.values(category)) {
          if ((product as any).id === productId) {
            foundProduct = product;
            break;
          }
        }
        if (foundProduct) break;
      }

      if (!foundProduct) {
        return res.status(404).json({
          success: false,
          error: `Product ${productId} not found`,
        });
      }

      // Get Stripe product details
      const manager = getProductManager();
      const stripeProduct = await manager.getProductById(productId);

      res.json({
        success: true,
        data: {
          ...foundProduct,
          stripeId: stripeProduct?.id,
          syncedToStripe: !!stripeProduct,
        },
      });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * GET /billing/products/category/:category
 * Get products by category with filtering
 */
enhancedBillingRouter.get(
  "/products/category/:category",
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { category } = req.params;
      const { sort = "name" } = req.query;

      const products = getProductsByCategory(category);

      // Sort products
      const sorted = products.sort((a: any, b: any) => {
        if (sort === "price") {
          const priceA = a.prices?.base || a.prices?.monthly || 0;
          const priceB = b.prices?.base || b.prices?.monthly || 0;
          return priceA - priceB;
        }
        return a.name.localeCompare(b.name);
      });

      res.json({
        success: true,
        data: {
          category,
          products: sorted,
          total: sorted.length,
        },
      });
    } catch (error) {
      next(error);
    }
  },
);

// ============================================================================
// PRICING & QUOTATION ENDPOINTS
// ============================================================================

/**
 * POST /billing/quote
 * Generate a shipping quote based on parameters
 */
enhancedBillingRouter.post(
  "/quote",
  requireScope("billing:read"),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const {
        serviceType,
        origin,
        destination,
        weight,
        distance,
        isHazmat = false,
        isTemperatureControlled = false,
        isWhiteGlove = false,
      } = req.body;

      if (!serviceType || !weight || !distance) {
        return res.status(400).json({
          success: false,
          error: "serviceType, weight, and distance are required for quote",
        });
      }

      // Find the product
      let basePrice = 0;
      let product: any = null;

      for (const category of Object.values(INFAMOUS_FREIGHT_PRODUCTS)) {
        for (const prod of Object.values(category)) {
          if ((prod as any).metadata?.serviceType === serviceType) {
            product = prod as any;
            basePrice = product.prices?.base || 0;
            break;
          }
        }
        if (product) break;
      }

      if (!product) {
        return res.status(404).json({
          success: false,
          error: `Service type ${serviceType} not found`,
        });
      }

      // Calculate quote
      let total = basePrice;
      const charges: any = { base: basePrice };

      // Add distance charges
      if (product.prices?.perMile) {
        const distanceCharge = distance * product.prices.perMile;
        charges.distance = distanceCharge;
        total += distanceCharge;
      }

      // Add weight charges
      if (product.prices?.perPound) {
        const weightCharge = weight * product.prices.perPound;
        charges.weight = weightCharge;
        total += weightCharge;
      }

      // Add surcharges
      if (
        isHazmat &&
        INFAMOUS_FREIGHT_PRODUCTS.specialtyServices.hazmatShipping
      ) {
        charges.hazmat =
          INFAMOUS_FREIGHT_PRODUCTS.specialtyServices.hazmatShipping.prices.surcharge;
        total += charges.hazmat;
      }

      if (
        isTemperatureControlled &&
        INFAMOUS_FREIGHT_PRODUCTS.specialtyServices.temperatureControlled
      ) {
        charges.temperatureControl =
          INFAMOUS_FREIGHT_PRODUCTS.specialtyServices.temperatureControlled.prices.surcharge;
        total += charges.temperatureControl;
      }

      if (
        isWhiteGlove &&
        INFAMOUS_FREIGHT_PRODUCTS.specialtyServices.whiteGloveDelivery
      ) {
        charges.whiteGlove =
          INFAMOUS_FREIGHT_PRODUCTS.specialtyServices.whiteGloveDelivery.prices.surcharge;
        total += charges.whiteGlove;
      }

      res.json({
        success: true,
        data: {
          quote: {
            serviceType,
            origin,
            destination,
            weight,
            distance,
            charges,
            total,
            totalUSD: (total / 100).toFixed(2),
            estimatedDelivery: product.metadata?.sla,
            quoteExpiry: new Date(
              Date.now() + 24 * 60 * 60 * 1000,
            ).toISOString(),
          },
        },
      });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * POST /billing/bulk-pricing
 * Get bulk pricing discounts
 */
enhancedBillingRouter.post(
  "/bulk-pricing",
  requireScope("billing:read"),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { serviceType, volume } = req.body;

      if (!serviceType || !volume) {
        return res.status(400).json({
          success: false,
          error: "serviceType and volume are required",
        });
      }

      // Find base price
      let basePrice = 0;
      for (const category of Object.values(INFAMOUS_FREIGHT_PRODUCTS)) {
        for (const product of Object.values(category)) {
          if ((product as any).metadata?.serviceType === serviceType) {
            basePrice = (product as any).prices?.base || 0;
            break;
          }
        }
      }

      if (basePrice === 0) {
        return res.status(404).json({
          success: false,
          error: `Service type ${serviceType} not found`,
        });
      }

      // Calculate tiered discounts
      const tiers = [
        { min: 1, max: 10, discount: 0 },
        { min: 11, max: 50, discount: 0.05 },
        { min: 51, max: 100, discount: 0.1 },
        { min: 101, max: 500, discount: 0.15 },
        { min: 501, max: Infinity, discount: 0.2 },
      ];

      const tier = tiers.find((t) => volume >= t.min && volume <= t.max);
      const discount = tier?.discount || 0;
      const unitPrice = basePrice * (1 - discount);
      const totalPrice = unitPrice * volume;

      res.json({
        success: true,
        data: {
          bulk: {
            serviceType,
            volume,
            basePrice,
            discountPercent: (discount * 100).toFixed(1),
            unitPrice: unitPrice / 100,
            totalPrice: totalPrice / 100,
            savings: ((basePrice - unitPrice) * volume) / 100,
          },
        },
      });
    } catch (error) {
      next(error);
    }
  },
);

// ============================================================================
// STRIPE MANAGEMENT ENDPOINTS
// ============================================================================

/**
 * POST /billing/stripe/sync-products
 * Manually sync products to Stripe
 */
enhancedBillingRouter.post(
  "/stripe/sync-products",
  requireScope("billing:admin"),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const manager = getProductManager();
      const result = await manager.syncAllProducts();

      res.json({
        success: true,
        data: {
          sync: result,
          message: `Successfully synced ${result.created} products, updated ${result.updated}`,
        },
      });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * GET /billing/stripe/pricing-summary
 * Get pricing summary for all products
 */
enhancedBillingRouter.get(
  "/stripe/pricing-summary",
  requireScope("billing:read"),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const manager = getProductManager();
      const summary = await manager.getPricingSummary();

      res.json({
        success: true,
        data: summary,
      });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * POST /billing/stripe/checkout
 * Create a Stripe checkout session for a product
 */
enhancedBillingRouter.post(
  "/stripe/checkout",
  requireScope("billing:write"),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { productId, quantity = 1, successUrl, cancelUrl } = req.body;

      if (!productId || !successUrl || !cancelUrl) {
        return res.status(400).json({
          success: false,
          error: "productId, successUrl, and cancelUrl are required",
        });
      }

      const manager = getProductManager();
      const session = await manager.createCheckoutSession(productId, quantity, {
        success: successUrl,
        cancel: cancelUrl,
      });

      res.json({
        success: true,
        data: {
          sessionId: session.id,
          sessionUrl: session.url,
          productId,
        },
      });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * GET /billing/stripe/products
 * Get all products synced to Stripe
 */
enhancedBillingRouter.get(
  "/stripe/products",
  requireScope("billing:read"),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const manager = getProductManager();
      const products = await manager.getAllSyncedProducts();

      const formatted = await Promise.all(
        products.map(async (p) => {
          const prices = await manager.getProductPrices(p.id);
          return {
            id: p.id,
            name: p.name,
            description: p.description,
            metadata: p.metadata,
            prices: prices.map((pr) => ({
              id: pr.id,
              amount: pr.unit_amount,
              currency: pr.currency,
              recurring: pr.recurring
                ? `${pr.recurring.interval}ly`
                : "one-time",
            })),
          };
        }),
      );

      res.json({
        success: true,
        data: {
          products: formatted,
          total: formatted.length,
        },
      });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * GET /billing/stripe/products/:productId
 * Get detailed Stripe product
 */
enhancedBillingRouter.get(
  "/stripe/products/:productId",
  requireScope("billing:read"),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { productId } = req.params;
      const manager = getProductManager();

      const product = await manager.getProductById(productId);
      if (!product) {
        return res.status(404).json({
          success: false,
          error: `Product ${productId} not found in Stripe`,
        });
      }

      const prices = await manager.getProductPrices(product.id);

      res.json({
        success: true,
        data: {
          id: product.id,
          name: product.name,
          description: product.description,
          metadata: product.metadata,
          prices: prices.map((p) => ({
            id: p.id,
            amount: p.unit_amount,
            currency: p.currency,
            recurring: p.recurring
              ? {
                  interval: p.recurring.interval,
                  intervalCount: p.recurring.interval_count,
                }
              : null,
          })),
        },
      });
    } catch (error) {
      next(error);
    }
  },
);

// ============================================================================
// SUBSCRIPTION MANAGEMENT ENDPOINTS
// ============================================================================

/**
 * POST /billing/subscriptions
 * Create a subscription to a product
 */
enhancedBillingRouter.post(
  "/subscriptions",
  requireScope("billing:write"),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { productId, priceId } = req.body;

      if (!productId && !priceId) {
        return res.status(400).json({
          success: false,
          error: "Either productId or priceId is required",
        });
      }

      // Create subscription in Stripe
      const stripe = getStripeClient();
      const subscription = await stripe.subscriptions.create({
        items: [
          {
            price: priceId,
          },
        ],
        metadata: {
          productId,
          customerId: req.user?.sub,
        },
      });

      res.json({
        success: true,
        data: {
          subscription: {
            id: subscription.id,
            status: subscription.status,
            priceId,
            items: subscription.items.data,
          },
        },
      });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * GET /billing/subscriptions
 * List subscriptions for user
 */
enhancedBillingRouter.get(
  "/subscriptions",
  requireScope("billing:read"),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const stripe = getStripeClient();
      const subscriptions = await stripe.subscriptions.list({
        metadata: {
          customerId: req.user?.sub,
        },
        limit: 100,
      });

      res.json({
        success: true,
        data: {
          subscriptions: subscriptions.data.map((sub) => ({
            id: sub.id,
            status: sub.status,
            items: sub.items.data,
            currentPeriodStart: sub.current_period_start,
            currentPeriodEnd: sub.current_period_end,
          })),
          total: subscriptions.data.length,
        },
      });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * POST /billing/subscriptions/:subscriptionId/cancel
 * Cancel a subscription
 */
enhancedBillingRouter.post(
  "/subscriptions/:subscriptionId/cancel",
  requireScope("billing:write"),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { subscriptionId } = req.params;
      const stripe = getStripeClient();

      const subscription = await stripe.subscriptions.cancel(subscriptionId);

      res.json({
        success: true,
        data: {
          subscription: {
            id: subscription.id,
            status: subscription.status,
            canceledAt: subscription.canceled_at,
          },
        },
      });
    } catch (error) {
      next(error);
    }
  },
);

export default enhancedBillingRouter;

/**
 * Stripe Products Sync Service
 * Syncs Infamous Freight products to Stripe and manages pricing
 */

import Stripe from "stripe";
import {
  INFAMOUS_FREIGHT_PRODUCTS,
  formatProductForStripe,
  formatPrice,
} from "./products";

const stripeApiVersion = "2024-06-20" as Stripe.LatestApiVersion;

export class StripeProductsManager {
  private stripe: Stripe;

  constructor(apiKey: string) {
    this.stripe = new Stripe(apiKey, { apiVersion: stripeApiVersion });
  }

  /**
   * Sync all products to Stripe
   * Creates products and prices, handles updates
   */
  async syncAllProducts(): Promise<{
    created: number;
    updated: number;
    failed: number;
  }> {
    let created = 0;
    let updated = 0;
    let failed = 0;

    console.log("🚀 Starting product sync to Stripe...");

    for (const [_, category] of Object.entries(INFAMOUS_FREIGHT_PRODUCTS)) {
      for (const [_, product] of Object.entries(category)) {
        try {
          const result = await this.syncProduct(product as any);
          if (result.isNew) created++;
          else updated++;

          console.log(`✅ ${product.name} - ${result.stripeId}`);
        } catch (error) {
          failed++;
          console.error(`❌ Failed to sync ${product.name}:`, error);
        }
      }
    }

    console.log(
      `\n📊 Sync complete: ${created} created, ${updated} updated, ${failed} failed`,
    );

    return { created, updated, failed };
  }

  /**
   * Sync a single product
   */
  async syncProduct(
    product: any,
  ): Promise<{ stripeId: string; isNew: boolean }> {
    // Format product data for Stripe
    const productData = formatProductForStripe(product);

    // Check if product exists
    const existingProduct = await this.findProductByMetadata(
      "productId",
      product.id,
    );

    let stripeProduct: Stripe.Product;

    if (existingProduct) {
      // Update existing product
      stripeProduct = await this.stripe.products.update(existingProduct.id, {
        ...productData,
        metadata: {
          ...productData.metadata,
          lastSyncedAt: new Date().toISOString(),
        },
      });
    } else {
      // Create new product
      stripeProduct = await this.stripe.products.create({
        ...productData,
        metadata: {
          ...productData.metadata,
          createdAt: new Date().toISOString(),
          lastSyncedAt: new Date().toISOString(),
        },
      });
    }

    // Sync prices
    await this.syncPrices(stripeProduct.id, product);

    return {
      stripeId: stripeProduct.id,
      isNew: !existingProduct,
    };
  }

  /**
   * Sync prices for a product
   */
  private async syncPrices(
    stripeProductId: string,
    product: any,
  ): Promise<void> {
    const prices = this.extractPrices(product);

    for (const price of prices) {
      try {
        await this.stripe.prices.create({
          product: stripeProductId,
          ...price.data,
          metadata: {
            productId: product.id,
            pricingType: price.type,
            createdAt: new Date().toISOString(),
          },
        });
      } catch (error: any) {
        // Price might already exist, that's okay
        if (error.code !== "resource_already_exists") {
          throw error;
        }
      }
    }
  }

  /**
   * Extract prices from product object
   */
  private extractPrices(product: any): Array<{ type: string; data: any }> {
    const prices: Array<{ type: string; data: any }> = [];

    if (product.prices) {
      // Handle different price structures

      if (product.prices.base) {
        // Per-unit/base pricing
        prices.push({
          type: "base",
          data: formatPrice(product.prices.base),
        });
      }

      if (product.prices.monthly) {
        // Subscription monthly
        prices.push({
          type: "monthly",
          data: {
            currency: "usd",
            unit_amount: product.prices.monthly,
            recurring: {
              interval: "month",
              interval_count: 1,
            },
            billing_scheme: "per_unit",
          },
        });
      }

      if (product.prices.annual) {
        // Subscription annual
        prices.push({
          type: "annual",
          data: {
            currency: "usd",
            unit_amount: product.prices.annual,
            recurring: {
              interval: "year",
              interval_count: 1,
            },
            billing_scheme: "per_unit",
          },
        });
      }

      // Handle per-unit pricing
      if (product.prices.perMile) {
        prices.push({
          type: "per_mile",
          data: {
            currency: "usd",
            unit_amount: product.prices.perMile,
            billing_scheme: "tiered",
          },
        });
      }

      if (product.prices.perPound) {
        prices.push({
          type: "per_pound",
          data: {
            currency: "usd",
            unit_amount: product.prices.perPound,
            billing_scheme: "tiered",
          },
        });
      }

      if (product.prices.surcharge) {
        prices.push({
          type: "surcharge",
          data: formatPrice(product.prices.surcharge),
        });
      }

      if (product.prices.perDriver) {
        prices.push({
          type: "per_driver",
          data: {
            currency: "usd",
            unit_amount: product.prices.perDriver,
            recurring: {
              interval: "month",
              interval_count: 1,
            },
          },
        });
      }

      if (product.prices.perVehicle) {
        prices.push({
          type: "per_vehicle",
          data: {
            currency: "usd",
            unit_amount: product.prices.perVehicle,
            recurring: {
              interval: "month",
              interval_count: 1,
            },
          },
        });
      }
    }

    return prices;
  }

  /**
   * Find product by metadata
   */
  private async findProductByMetadata(
    key: string,
    value: string,
  ): Promise<Stripe.Product | null> {
    const products = await this.stripe.products.list({
      limit: 100,
      active: true,
    });

    return (
      products.data.find((p) => p.metadata && p.metadata[key] === value) || null
    );
  }

  /**
   * Get all Stripe products with our metadata
   */
  async getAllSyncedProducts(): Promise<Stripe.Product[]> {
    const products: Stripe.Product[] = [];
    let startingAfter: string | undefined;

    while (true) {
      const page = await this.stripe.products.list({
        limit: 100,
        active: true,
        starting_after: startingAfter,
      });

      products.push(
        ...page.data.filter((p) => p.metadata && p.metadata.productId),
      );

      if (!page.has_more) break;
      startingAfter = page.data[page.data.length - 1].id;
    }

    return products;
  }

  /**
   * Get product by internal ID
   */
  async getProductById(productId: string): Promise<Stripe.Product | null> {
    return this.findProductByMetadata("productId", productId);
  }

  /**
   * Get all prices for a product
   */
  async getProductPrices(stripeProductId: string): Promise<Stripe.Price[]> {
    const prices = await this.stripe.prices.list({
      product: stripeProductId,
      limit: 100,
    });

    return prices.data;
  }

  /**
   * Update product pricing
   */
  async updateProductPricing(productId: string, newPrices: any): Promise<void> {
    const stripeProduct = await this.getProductById(productId);
    if (!stripeProduct) {
      throw new Error(`Product ${productId} not found in Stripe`);
    }

    // Deactivate old prices
    const oldPrices = await this.getProductPrices(stripeProduct.id);
    for (const price of oldPrices) {
      await this.stripe.prices.update(price.id, { active: false });
    }

    // Create new prices
    const prices = newPrices.prices || newPrices;
    for (const [key, value] of Object.entries(prices)) {
      await this.stripe.prices.create({
        product: stripeProduct.id,
        ...(typeof value === "number"
          ? formatPrice(value)
          : { ...value, currency: "usd" }),
        metadata: {
          pricingType: key,
          updatedAt: new Date().toISOString(),
        },
      });
    }
  }

  /**
   * Create a checkout session for a product
   */
  async createCheckoutSession(
    productId: string,
    quantity: number = 1,
    returnUrl: { success: string; cancel: string },
  ): Promise<Stripe.Checkout.Session> {
    const stripeProduct = await this.getProductById(productId);
    if (!stripeProduct) {
      throw new Error(`Product ${productId} not found`);
    }

    const prices = await this.getProductPrices(stripeProduct.id);
    if (prices.length === 0) {
      throw new Error(`No prices found for product ${productId}`);
    }

    return this.stripe.checkout.sessions.create({
      mode: prices[0].recurring ? "subscription" : "payment",
      customer_email: undefined,
      line_items: [
        {
          price: prices[0].id,
          quantity,
        },
      ],
      success_url: returnUrl.success,
      cancel_url: returnUrl.cancel,
    });
  }

  /**
   * Get pricing summary for all products
   */
  async getPricingSummary(): Promise<any> {
    const products = await this.getAllSyncedProducts();

    const summary = {
      totalProducts: products.length,
      byCategory: {} as Record<string, number>,
      priceRanges: {
        oneTime: { min: Infinity, max: 0, count: 0 },
        subscription: { min: Infinity, max: 0, count: 0 },
      },
      products: [] as any[],
    };

    for (const product of products) {
      const category = product.metadata?.category || "uncategorized";
      summary.byCategory[category] = (summary.byCategory[category] || 0) + 1;

      const prices = await this.getProductPrices(product.id);
      const productInfo = {
        id: product.id,
        name: product.name,
        category,
        prices: prices.map((p) => ({
          id: p.id,
          amount: p.unit_amount,
          currency: p.currency,
          recurring: p.recurring ? `${p.recurring.interval}ly` : "one-time",
        })),
      };

      summary.products.push(productInfo);

      // Update price ranges
      for (const price of prices) {
        if (price.unit_amount) {
          if (price.recurring) {
            summary.priceRanges.subscription.min = Math.min(
              summary.priceRanges.subscription.min,
              price.unit_amount,
            );
            summary.priceRanges.subscription.max = Math.max(
              summary.priceRanges.subscription.max,
              price.unit_amount,
            );
            summary.priceRanges.subscription.count++;
          } else {
            summary.priceRanges.oneTime.min = Math.min(
              summary.priceRanges.oneTime.min,
              price.unit_amount,
            );
            summary.priceRanges.oneTime.max = Math.max(
              summary.priceRanges.oneTime.max,
              price.unit_amount,
            );
            summary.priceRanges.oneTime.count++;
          }
        }
      }
    }

    return summary;
  }
}

/**
 * Initialize and sync all products
 */
export async function initializeStripeProducts(
  stripeKey: string,
): Promise<void> {
  const manager = new StripeProductsManager(stripeKey);

  try {
    const result = await manager.syncAllProducts();
    const summary = await manager.getPricingSummary();

    console.log("\n📋 Product Sync Summary:");
    console.log(`   Total Products: ${summary.totalProducts}`);
    console.log(`   By Category:`);
    for (const [category, count] of Object.entries(summary.byCategory)) {
      console.log(`     - ${category}: ${count}`);
    }

    console.log(`\n💰 Pricing Ranges:`);
    console.log(
      `   One-Time: $${(summary.priceRanges.oneTime.min / 100).toFixed(2)} - $${(summary.priceRanges.oneTime.max / 100).toFixed(2)} (${summary.priceRanges.oneTime.count} prices)`,
    );
    console.log(
      `   Subscription: $${(summary.priceRanges.subscription.min / 100).toFixed(2)} - $${(summary.priceRanges.subscription.max / 100).toFixed(2)}/month (${summary.priceRanges.subscription.count} prices)`,
    );
  } catch (error) {
    console.error("❌ Failed to initialize Stripe products:", error);
    throw error;
  }
}

export default StripeProductsManager;

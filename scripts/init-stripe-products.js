#!/usr/bin/env node

/**
 * Stripe Products Initialization Script
 * Syncs all Infamous Freight products to Stripe
 * Run: node scripts/init-stripe-products.js
 */

import "dotenv/config";
import { initializeStripeProducts } from "../src/lib/stripeProductsManager.js";
import { INFAMOUS_FREIGHT_PRODUCTS, PRICING_REFERENCE } from "../src/lib/products.js";

const stripeKey = process.env.STRIPE_SECRET_KEY;

if (!stripeKey) {
    console.error(
        "❌ STRIPE_SECRET_KEY environment variable not set. Please configure your Stripe API key."
    );
    process.exit(1);
}

console.log(`
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║    🚀 Infamous Freight - Stripe Products Initialization   ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
`);

console.log(`📅 Pricing Updated: ${PRICING_REFERENCE.lastUpdated}`);
console.log(`🌍 Market Conditions: ${PRICING_REFERENCE.marketConditions}\n`);

// Count products
let totalProducts = 0;
const productsByCategory: Record<string, number> = {};

for (const [categoryName, category] of Object.entries(INFAMOUS_FREIGHT_PRODUCTS)) {
    const count = Object.keys(category).length;
    totalProducts += count;
    productsByCategory[categoryName] = count;
}

console.log(`📊 Product Summary:`);
console.log(`   Total Products: ${totalProducts}\n`);
console.log(`   Products by Category:`);
for (const [category, count] of Object.entries(productsByCategory)) {
    console.log(`   ✓ ${category}: ${count} products`);
}

console.log(`\n💰 Pricing Information:`);
console.log(`   Service Categories: ${Object.keys(INFAMOUS_FREIGHT_PRODUCTS).length}`);

// Show sample products
console.log(`\n📦 Sample Products:`);
const allCategories = Object.entries(INFAMOUS_FREIGHT_PRODUCTS);
const samples = allCategories.slice(0, 3);

for (const [categoryName, products] of samples) {
    console.log(`\n   ${categoryName.toUpperCase()}:`);
    const productEntries = Object.entries(products).slice(0, 2);
    for (const [_, product]: any) {
        const basePrice = product.prices?.base || product.prices?.monthly || 0;
    const priceUSD = (basePrice / 100).toFixed(2);
    console.log(
        `   ├─ ${product.name} - $${priceUSD}${product.prices?.monthly ? "/mo" : ""}`
    );
}
}

console.log(`\n`);

// Run initialization
(async () => {
    try {
        console.log(`🔄 Syncing products to Stripe...\n`);
        await initializeStripeProducts(stripeKey);

        console.log(`
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║           ✅ INITIALIZATION COMPLETE                       ║
║                                                            ║
║     All Infamous Freight products synced to Stripe!        ║
║                                                            ║
║  Next steps:                                               ║
║  1. Verify products in Stripe Dashboard                    ║
║  2. Set up webhooks for payment events                     ║
║  3. Configure success/cancel URLs in config               ║
║  4. Deploy to production                                   ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
    `);

        process.exit(0);
    } catch (error) {
        console.error(`\n❌ Initialization failed:`);
        console.error(error);
        process.exit(1);
    }
})();

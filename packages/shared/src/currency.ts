/**
 * Multi-Currency Support for International Expansion
 *
 * Supports:
 * - USD (United States Dollar) - Default
 * - EUR (Euro) - European markets
 * - GBP (British Pound) - UK market
 * - CAD (Canadian Dollar) - Canada market
 * - MXN (Mexican Peso) - Mexico market
 */

export interface Currency {
  code: string;
  symbol: string;
  name: string;
  decimals: number;
  symbolPosition: "before" | "after";
  thousandsSeparator: string;
  decimalSeparator: string;
}

export const SUPPORTED_CURRENCIES: Record<string, Currency> = {
  USD: {
    code: "USD",
    symbol: "$",
    name: "US Dollar",
    decimals: 2,
    symbolPosition: "before",
    thousandsSeparator: ",",
    decimalSeparator: ".",
  },
  EUR: {
    code: "EUR",
    symbol: "€",
    name: "Euro",
    decimals: 2,
    symbolPosition: "after",
    thousandsSeparator: ".",
    decimalSeparator: ",",
  },
  GBP: {
    code: "GBP",
    symbol: "£",
    name: "British Pound",
    decimals: 2,
    symbolPosition: "before",
    thousandsSeparator: ",",
    decimalSeparator: ".",
  },
  CAD: {
    code: "CAD",
    symbol: "C$",
    name: "Canadian Dollar",
    decimals: 2,
    symbolPosition: "before",
    thousandsSeparator: ",",
    decimalSeparator: ".",
  },
  MXN: {
    code: "MXN",
    symbol: "Mex$",
    name: "Mexican Peso",
    decimals: 2,
    symbolPosition: "before",
    thousandsSeparator: ",",
    decimalSeparator: ".",
  },
};

/**
 * Exchange rates (relative to USD)
 * In production, fetch from external API (e.g., exchangerate-api.com)
 */
export interface ExchangeRates {
  base: string;
  rates: Record<string, number>;
  lastUpdated: Date;
}

/**
 * Format currency for display
 */
export function formatCurrency(
  amount: number,
  currencyCode: string = "USD",
  locale?: string,
): string {
  const currency =
    SUPPORTED_CURRENCIES[currencyCode] || SUPPORTED_CURRENCIES.USD;

  // Use Intl.NumberFormat for proper localization
  const formatter = new Intl.NumberFormat(locale || "en-US", {
    style: "currency",
    currency: currencyCode,
    minimumFractionDigits: currency.decimals,
    maximumFractionDigits: currency.decimals,
  });

  return formatter.format(amount);
}

/**
 * Convert amount from one currency to another
 */
export async function convertCurrency(
  amount: number,
  fromCurrency: string,
  toCurrency: string,
): Promise<number> {
  if (fromCurrency === toCurrency) {
    return amount;
  }

  // In production, fetch live rates from API
  const rates = await getExchangeRates();

  // Convert from source to USD, then USD to target
  const amountInUSD =
    fromCurrency === "USD" ? amount : amount / rates.rates[fromCurrency];

  const convertedAmount =
    toCurrency === "USD" ? amountInUSD : amountInUSD * rates.rates[toCurrency];

  return convertedAmount;
}

/**
 * Get current exchange rates
 */
export async function getExchangeRates(): Promise<ExchangeRates> {
  // In production, fetch from external API with caching
  // Example: https://api.exchangerate-api.com/v4/latest/USD

  // Mock rates for development
  return {
    base: "USD",
    rates: {
      USD: 1.0,
      EUR: 0.92, // 1 USD = 0.92 EUR
      GBP: 0.79, // 1 USD = 0.79 GBP
      CAD: 1.36, // 1 USD = 1.36 CAD
      MXN: 17.12, // 1 USD = 17.12 MXN
    },
    lastUpdated: new Date(),
  };
}

/**
 * Parse currency string to number
 */
export function parseCurrency(
  value: string,
  currencyCode: string = "USD",
): number {
  const currency =
    SUPPORTED_CURRENCIES[currencyCode] || SUPPORTED_CURRENCIES.USD;

  // Remove currency symbol and thousands separators
  let cleaned = value
    .replace(currency.symbol, "")
    .replace(new RegExp(`\\${currency.thousandsSeparator}`, "g"), "")
    .trim();

  // Replace decimal separator with standard dot
  if (currency.decimalSeparator !== ".") {
    cleaned = cleaned.replace(currency.decimalSeparator, ".");
  }

  return parseFloat(cleaned) || 0;
}

/**
 * Get user's preferred currency from browser/settings
 */
export function detectUserCurrency(): string {
  // Try to detect from browser locale
  if (typeof navigator !== "undefined") {
    const locale = navigator.language;
    const currencyMap: Record<string, string> = {
      "en-US": "USD",
      "en-GB": "GBP",
      "en-CA": "CAD",
      "es-MX": "MXN",
      "de-DE": "EUR",
      "fr-FR": "EUR",
      "it-IT": "EUR",
      "es-ES": "EUR",
    };

    return currencyMap[locale] || "USD";
  }

  return "USD";
}

/**
 * Stripe multi-currency support
 */
export async function createStripePrice(
  amount: number,
  currencyCode: string,
  productId: string,
): Promise<string> {
  // In production with Stripe:
  // const price = await stripe.prices.create({
  //   product: productId,
  //   currency: currencyCode.toLowerCase(),
  //   unit_amount: Math.round(amount * 100), // Stripe uses cents
  //   recurring: { interval: 'month' },
  // });
  // return price.id;

  // Mock price ID
  return `price_${currencyCode}_${productId}_${Date.now()}`;
}

/**
 * Display price in multiple currencies
 */
export async function displayMultiCurrencyPrices(
  baseAmount: number,
  baseCurrency: string = "USD",
): Promise<Record<string, string>> {
  const rates = await getExchangeRates();
  const prices: Record<string, string> = {};

  for (const [code, currency] of Object.entries(SUPPORTED_CURRENCIES)) {
    const converted = await convertCurrency(baseAmount, baseCurrency, code);
    prices[code] = formatCurrency(converted, code);
  }

  return prices;
}

/**
 * Localize pricing page for region
 */
export async function getLocalizedPricing(userCurrency: string) {
  // Starter plan
  const starterUSD = 99.99;
  const starterLocal = await convertCurrency(starterUSD, "USD", userCurrency);

  // Professional plan
  const proUSD = 299.99;
  const proLocal = await convertCurrency(proUSD, "USD", userCurrency);

  // Enterprise plan
  const enterpriseUSD = 999.99;
  const enterpriseLocal = await convertCurrency(
    enterpriseUSD,
    "USD",
    userCurrency,
  );

  return {
    currency: userCurrency,
    starter: {
      monthly: formatCurrency(starterLocal, userCurrency),
      yearly: formatCurrency(starterLocal * 10, userCurrency), // 2 months free
    },
    professional: {
      monthly: formatCurrency(proLocal, userCurrency),
      yearly: formatCurrency(proLocal * 10, userCurrency),
    },
    enterprise: {
      monthly: formatCurrency(enterpriseLocal, userCurrency),
      yearly: formatCurrency(enterpriseLocal * 10, userCurrency),
    },
  };
}

/**
 * Currency conversion disclaimer
 */
export function getCurrencyDisclaimer(currency: string): string {
  if (currency === "USD") {
    return "All prices in US Dollars (USD).";
  }

  return `Prices shown in ${SUPPORTED_CURRENCIES[currency]?.name} are estimates based on current exchange rates. You will be charged in your local currency. Final amount may vary slightly.`;
}

export default {
  SUPPORTED_CURRENCIES,
  formatCurrency,
  convertCurrency,
  getExchangeRates,
  parseCurrency,
  detectUserCurrency,
  displayMultiCurrencyPrices,
  getLocalizedPricing,
  getCurrencyDisclaimer,
};

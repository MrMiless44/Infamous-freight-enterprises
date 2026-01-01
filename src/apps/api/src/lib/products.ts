/**
 * Infamous Freight Products for Stripe
 * Real-world shipping and logistics pricing (January 2026)
 * Fully integrated with Stripe platform
 */

export const INFAMOUS_FREIGHT_PRODUCTS = {
  // SHIPPING SERVICES
  shipping: {
    localDelivery: {
      id: "prod_local_delivery",
      name: "Local Delivery (0-50 miles)",
      description: "Same-day or next-day local delivery service",
      category: "shipping",
      prices: {
        base: 4500, // $45.00
        perMile: 50, // $0.50 per mile
        minCharge: 4500,
      },
      metadata: {
        maxDistance: 50,
        minDistance: 0,
        maxWeight: 5000, // lbs
        serviceType: "local",
        sla: "24-48 hours",
      },
    },
    regionalShipping: {
      id: "prod_regional_shipping",
      name: "Regional Shipping (50-500 miles)",
      description: "2-5 business day regional delivery",
      category: "shipping",
      prices: {
        base: 7500, // $75.00
        perMile: 35, // $0.35 per mile
        minCharge: 7500,
      },
      metadata: {
        maxDistance: 500,
        minDistance: 50,
        maxWeight: 20000, // lbs
        serviceType: "regional",
        sla: "2-5 business days",
      },
    },
    crossCountry: {
      id: "prod_cross_country",
      name: "Cross-Country Shipping",
      description: "Coast-to-coast and nationwide delivery (3-7 days)",
      category: "shipping",
      prices: {
        base: 15000, // $150.00
        perMile: 20, // $0.20 per mile
        minCharge: 15000,
      },
      metadata: {
        maxDistance: 3000,
        minDistance: 500,
        maxWeight: 45000, // lbs
        serviceType: "long_distance",
        sla: "3-7 business days",
      },
    },
    fullTruckLoad: {
      id: "prod_full_truck_load",
      name: "Full Truck Load (FTL)",
      description: "Dedicated truck for large shipments (53ft trailer)",
      category: "shipping",
      prices: {
        base: 250000, // $2,500.00
        perMile: 150, // $1.50 per mile
        minCharge: 250000,
      },
      metadata: {
        maxWeight: 45000,
        maxDistance: 3000,
        truckType: "53ft_trailer",
        capacity: "up to 45,000 lbs",
        serviceType: "ftl",
        sla: "2-7 business days",
      },
    },
    ltlShipping: {
      id: "prod_ltl_shipping",
      name: "Less Than Truck Load (LTL)",
      description: "Shared truck space for partial loads",
      category: "shipping",
      prices: {
        base: 5000, // $50.00
        perPound: 2, // $0.02 per pound
        minCharge: 5000,
      },
      metadata: {
        maxWeight: 10000,
        serviceType: "ltl",
        consolidation: "yes",
        sla: "3-5 business days",
      },
    },
    internationalShipping: {
      id: "prod_international_shipping",
      name: "International Shipping",
      description: "Cross-border and international delivery",
      category: "shipping",
      prices: {
        base: 50000, // $500.00
        perPound: 5, // $0.05 per pound
        minCharge: 50000,
      },
      metadata: {
        serviceType: "international",
        customsHandling: "yes",
        insurance: "included",
        sla: "7-21 business days",
        regions: ["Canada", "Mexico", "EU", "APAC"],
      },
    },
    expressOvernight: {
      id: "prod_express_overnight",
      name: "Express Overnight",
      description: "Priority overnight delivery service",
      category: "shipping",
      prices: {
        base: 20000, // $200.00
        perMile: 100, // $1.00 per mile
        minCharge: 20000,
      },
      metadata: {
        maxDistance: 500,
        serviceType: "express",
        guarantee: "next_business_day",
        sla: "Next business day before 9am",
      },
    },
  },

  // SPECIALTY SERVICES
  specialtyServices: {
    temperatureControlled: {
      id: "prod_temp_controlled",
      name: "Temperature-Controlled Shipping",
      description: "Climate-controlled transport for sensitive cargo",
      category: "specialty",
      prices: {
        surcharge: 5000, // $50.00 additional
      },
      metadata: {
        tempRange: "-40°F to 70°F",
        cargoTypes: ["pharmaceuticals", "perishables", "electronics", "food"],
        certifications: ["FDA", "USDA", "GMP"],
      },
    },
    hazmatShipping: {
      id: "prod_hazmat_shipping",
      name: "Hazmat Shipping",
      description: "Specialized handling for hazardous materials",
      category: "specialty",
      prices: {
        surcharge: 10000, // $100.00 additional
      },
      metadata: {
        certifications: ["DOT", "IATA", "IMDG"],
        training: "required",
        documentation: "full_manifest",
      },
    },
    whiteGloveDelivery: {
      id: "prod_white_glove",
      name: "White Glove Delivery",
      description: "Premium handling with unpacking and setup",
      category: "specialty",
      prices: {
        surcharge: 15000, // $150.00 additional
      },
      metadata: {
        includes: [
          "delivery",
          "unpacking",
          "positioning",
          "removal",
          "installation",
        ],
        coverage: "full_damage_protection",
      },
    },
    liftgateService: {
      id: "prod_liftgate",
      name: "Liftgate Service",
      description: "Tailgate lift for dock-less locations",
      category: "specialty",
      prices: {
        surcharge: 2500, // $25.00 additional
      },
      metadata: {
        capacity: "5000 lbs",
        availability: "most_trucks",
      },
    },
    insideDelivery: {
      id: "prod_inside_delivery",
      name: "Inside Delivery",
      description: "Delivery to warehouse or loading dock",
      category: "specialty",
      prices: {
        surcharge: 5000, // $50.00 additional
      },
      metadata: {
        includes: ["delivery_to_room", "placement", "debris_removal"],
      },
    },
    cargoInsurance: {
      id: "prod_cargo_insurance",
      name: "Cargo Insurance",
      description: "Additional insurance coverage for high-value items",
      category: "specialty",
      prices: {
        coverage1k: 250, // $2.50 per $1000 value
        coverage10k: 200, // $2.00 per $1000 value
        coverage100k: 150, // $1.50 per $1000 value
      },
      metadata: {
        coverage: "all_risks",
        deductible: 500,
        claims: "48_hour_processing",
      },
    },
  },

  // VALUE-ADDED SERVICES
  valueAddedServices: {
    packageTracking: {
      id: "prod_tracking",
      name: "Real-Time Package Tracking",
      description: "GPS tracking and live updates",
      category: "value_added",
      prices: {
        singleShipment: 500, // $5.00
        monthlyUnlimited: 2999, // $29.99
      },
      metadata: {
        updateFrequency: "real_time",
        notifications: ["sms", "email", "webhook"],
      },
    },
    deliveryNotification: {
      id: "prod_notifications",
      name: "Delivery Notifications",
      description: "SMS and email notifications for shipments",
      category: "value_added",
      prices: {
        monthly: 999, // $9.99
      },
      metadata: {
        channels: ["sms", "email", "push"],
        customization: "yes",
      },
    },
    proofOfDelivery: {
      id: "prod_pod",
      name: "Proof of Delivery (Photo/Signature)",
      description: "Photographic proof and digital signature capture",
      category: "value_added",
      prices: {
        surcharge: 1000, // $10.00 per shipment
      },
      metadata: {
        includes: ["photo", "signature", "timestamp", "gps_location"],
      },
    },
    dynamicPricing: {
      id: "prod_dynamic_pricing",
      name: "Dynamic Pricing Engine",
      description: "AI-powered pricing based on demand and capacity",
      category: "value_added",
      prices: {
        monthly: 4999, // $49.99
      },
      metadata: {
        optimization: "real_time",
        maxSavings: "25%",
        algorithms: "ml_based",
      },
    },
    consolidation: {
      id: "prod_consolidation",
      name: "Shipment Consolidation",
      description: "Combine multiple shipments for better rates",
      category: "value_added",
      prices: {
        surcharge: 2500, // $25.00
      },
      metadata: {
        savingsAverage: "15%",
        consolidationWindow: "24_hours",
      },
    },
    customs: {
      id: "prod_customs",
      name: "Customs Clearance",
      description: "Full customs documentation and clearance",
      category: "value_added",
      prices: {
        service: 15000, // $150.00
      },
      metadata: {
        includes: ["documentation", "filing", "broker_fees", "duty_payment"],
      },
    },
  },

  // SUBSCRIPTION PLANS
  subscriptionPlans: {
    starter: {
      id: "prod_starter_plan",
      name: "Starter Plan",
      description: "Perfect for small businesses",
      category: "subscription",
      prices: {
        monthly: 9999, // $99.99
        annual: 99999, // $999.99 (save $199.89)
      },
      metadata: {
        shipments: "100/month",
        users: 3,
        api: "basic",
        support: "email",
        analytics: "basic",
        features: [
          "basic_tracking",
          "email_support",
          "api_access",
          "monthly_reports",
        ],
      },
    },
    professional: {
      id: "prod_professional_plan",
      name: "Professional Plan",
      description: "For growing shipping businesses",
      category: "subscription",
      prices: {
        monthly: 29999, // $299.99
        annual: 299999, // $2,999.99 (save $600)
      },
      metadata: {
        shipments: "1000/month",
        users: 10,
        api: "standard",
        support: "phone_email",
        analytics: "advanced",
        features: [
          "realtime_tracking",
          "phone_support",
          "webhooks",
          "custom_integrations",
          "advanced_analytics",
          "dedicated_account_manager",
        ],
      },
    },
    enterprise: {
      id: "prod_enterprise_plan",
      name: "Enterprise Plan",
      description: "For large-scale logistics operations",
      category: "subscription",
      prices: {
        monthly: 99999, // $999.99 (custom pricing available)
        annual: 999999, // $9,999.99 (custom pricing available)
      },
      metadata: {
        shipments: "unlimited",
        users: "unlimited",
        api: "premium",
        support: "24/7",
        analytics: "custom",
        features: [
          "unlimited_tracking",
          "24/7_phone_support",
          "custom_api",
          "white_label",
          "custom_integrations",
          "dedicated_team",
          "sla_guarantee",
          "blockchain_verification",
        ],
      },
    },
    payPerUse: {
      id: "prod_pay_per_use",
      name: "Pay-Per-Use",
      description: "No monthly fees, pay only for shipments",
      category: "subscription",
      prices: {
        baseShipment: 2500, // $25.00 minimum per shipment
      },
      metadata: {
        usage: "per_shipment",
        users: "unlimited",
        api: "standard",
        support: "email",
        analytics: "basic",
        advantages: [
          "no_commitments",
          "scale_as_you_grow",
          "flexible",
          "perfect_for_startups",
        ],
      },
    },
  },

  // DRIVER & FLEET SERVICES
  driverServices: {
    driverApp: {
      id: "prod_driver_app",
      name: "Driver Mobile App",
      description: "AI-powered driver app with route optimization",
      category: "driver",
      prices: {
        perDriver: 499, // $4.99 per driver per month
      },
      metadata: {
        features: [
          "gps_tracking",
          "route_optimization",
          "real_time_updates",
          "voice_commands",
          "proof_of_delivery",
        ],
      },
    },
    driverDispatch: {
      id: "prod_driver_dispatch",
      name: "Intelligent Dispatch System",
      description: "AI-powered driver assignment and routing",
      category: "driver",
      prices: {
        monthly: 49999, // $499.99
      },
      metadata: {
        features: [
          "automatic_assignment",
          "ml_optimization",
          "traffic_aware",
          "capacity_planning",
          "predictive_maintenance",
        ],
      },
    },
    fleetTracking: {
      id: "prod_fleet_tracking",
      name: "Fleet Tracking & Management",
      description: "Complete fleet visibility and management",
      category: "driver",
      prices: {
        perVehicle: 999, // $9.99 per vehicle per month
      },
      metadata: {
        features: [
          "real_time_tracking",
          "maintenance_alerts",
          "fuel_monitoring",
          "driver_behavior",
          "compliance_reports",
        ],
      },
    },
  },

  // ANALYTICS & REPORTING
  analytics: {
    basicAnalytics: {
      id: "prod_basic_analytics",
      name: "Basic Analytics",
      description: "Shipment metrics and KPI tracking",
      category: "analytics",
      prices: {
        monthly: 999, // $9.99
      },
      metadata: {
        reports: ["monthly", "quarterly"],
        metrics: ["shipment_count", "avg_cost", "on_time_rate"],
      },
    },
    advancedAnalytics: {
      id: "prod_advanced_analytics",
      name: "Advanced Analytics",
      description: "Detailed analytics with predictive insights",
      category: "analytics",
      prices: {
        monthly: 4999, // $49.99
      },
      metadata: {
        reports: ["daily", "weekly", "monthly", "custom"],
        metrics: [
          "all_basic",
          "margin_analysis",
          "route_efficiency",
          "predictive_demand",
        ],
      },
    },
    customReporting: {
      id: "prod_custom_reporting",
      name: "Custom Reporting",
      description: "Tailored business intelligence reports",
      category: "analytics",
      prices: {
        monthly: 9999, // $99.99
      },
      metadata: {
        customization: "unlimited",
        frequency: "custom",
        dataWarehouse: "access",
      },
    },
  },
};

/**
 * Helper function to get all products
 */
export function getAllProducts() {
  return Object.values(INFAMOUS_FREIGHT_PRODUCTS).reduce(
    (acc, category) => ({ ...acc, ...category }),
    {},
  );
}

/**
 * Helper function to get products by category
 */
export function getProductsByCategory(category: string) {
  return Object.values(INFAMOUS_FREIGHT_PRODUCTS)
    .flatMap((cat) => Object.values(cat))
    .filter((prod: any) => prod.category === category);
}

/**
 * Helper function to format prices for Stripe
 */
export function formatPrice(cents: number, currency = "usd") {
  return {
    currency: currency.toLowerCase(),
    unit_amount: cents,
    recurring: undefined,
  };
}

/**
 * Helper function to format product data for Stripe
 */
export function formatProductForStripe(product: any) {
  return {
    name: product.name,
    description: product.description,
    metadata: {
      ...product.metadata,
      category: product.category,
      productId: product.id,
    },
    images: getProductImage(product.category, product.id),
    active: true,
  };
}

/**
 * Get product image URL based on category
 */
function getProductImage(category: string, productId: string): string[] {
  const imageMap: Record<string, string> = {
    shipping:
      "https://images.unsplash.com/photo-1453614512474-d021aafa-e37e?w=500",
    specialty:
      "https://images.unsplash.com/photo-1512427865486-a01bb6b214c7?w=500",
    value_added:
      "https://images.unsplash.com/photo-1460925895917-adf4ee868993?w=500",
    subscription:
      "https://images.unsplash.com/photo-1451187580459-43490279c0fa?w=500",
    driver:
      "https://images.unsplash.com/photo-1454496522488-7a8e488e8606?w=500",
    analytics:
      "https://images.unsplash.com/photo-1551288049-bebda4e38f71?w=500",
  };

  return imageMap[category] ? [imageMap[category]] : [];
}

/**
 * Real-world pricing reference (January 2026)
 * Based on actual freight industry rates
 */
export const PRICING_REFERENCE = {
  lastUpdated: "2026-01-01",
  marketConditions: "stable",
  notes: {
    localDelivery: "Typical rates for same-day/next-day service in metro areas",
    regionalShipping: "2-5 day service across state/region boundaries",
    crossCountry: "3-7 day coast-to-coast service with tracking",
    ftl: "Full truck load rates from $2,500 base, varies by distance/cargo",
    ltl: "Less-than-truck load rates for partial shipments",
    international: "Cross-border rates include customs, broker fees, insurance",
    express: "Premium overnight service at 150% of standard rates",
    specialtySurcharges:
      "Additional fees for temperature control, hazmat, white-glove, etc.",
    subscriptionPlans: "Monthly plans for regular shipping operations",
    driversAndFleet: "Per-vehicle and per-driver monthly SaaS fees",
  },
};

const { z } = require("zod");

/**
 * AI Command Schema (v1)
 * Validates command structure for AI endpoints
 */
const AiCommandSchema = z.object({
  command: z.string()
    .min(1, "Command cannot be empty")
    .max(200, "Command too long")
    .regex(/^[a-zA-Z0-9_-]+$/, "Command must contain only alphanumeric characters, underscores, and hyphens"),
  
  payload: z.record(z.any())
    .optional()
    .default({})
    .describe("Optional payload object with any structure"),
  
  meta: z.record(z.any())
    .optional()
    .default({})
    .describe("Optional metadata object")
});

/**
 * AI Command Schema v2
 * Enhanced with options support
 */
const AiCommandV2Schema = z.object({
  command: z.string()
    .min(1, "Command cannot be empty")
    .max(200, "Command too long")
    .regex(/^[a-zA-Z0-9_-]+$/, "Command must contain only alphanumeric characters, underscores, and hyphens"),
  
  payload: z.record(z.any())
    .optional()
    .default({})
    .describe("Optional payload object with any structure"),
  
  meta: z.record(z.any())
    .optional()
    .default({})
    .describe("Optional metadata object"),
  
  options: z.object({
    timeout: z.number().int().positive().max(30000).optional(),
    retryCount: z.number().int().min(0).max(3).optional(),
    priority: z.enum(['low', 'normal', 'high']).optional().default('normal')
  }).optional().default({})
});

/**
 * Batch AI Command Schema
 * For processing multiple commands at once
 */
const AiBatchCommandSchema = z.object({
  commands: z.array(AiCommandV2Schema)
    .min(1, "At least one command required")
    .max(10, "Maximum 10 commands per batch"),
  
  options: z.object({
    concurrency: z.number().int().min(1).max(10).optional(),
    stopOnError: z.boolean().optional().default(false)
  }).optional().default({})
});

/**
 * AI Query Schema
 * For simpler AI query endpoints
 */
const AiQuerySchema = z.object({
  query: z.string()
    .min(1, "Query cannot be empty")
    .max(1000, "Query too long"),
  
  model: z.enum(["gpt-4", "gpt-3.5-turbo", "claude-3", "synthetic"])
    .optional()
    .default("synthetic"),
  
  maxTokens: z.number()
    .int()
    .positive()
    .max(4000)
    .optional()
    .default(500)
});

/**
 * Voice Processing Schema
 */
const VoiceProcessingSchema = z.object({
  command: z.string()
    .min(1)
    .max(100),
  
  audioData: z.string()
    .optional()
    .describe("Base64 encoded audio data"),
  
  format: z.enum(["mp3", "wav", "ogg", "m4a"])
    .optional()
    .default("mp3"),
  
  language: z.string()
    .length(2)
    .optional()
    .default("en")
    .describe("ISO 639-1 language code")
});

/**
 * Billing Request Schema
 */
const BillingSchema = z.object({
  amount: z.number()
    .positive("Amount must be positive")
    .multipleOf(0.01, "Amount must have at most 2 decimal places"),
  
  currency: z.string()
    .length(3)
    .toUpperCase()
    .default("USD")
    .describe("ISO 4217 currency code"),
  
  description: z.string()
    .min(1)
    .max(500)
    .optional(),
  
  customerId: z.string()
    .uuid()
    .optional(),
  
  metadata: z.record(z.string())
    .optional()
});

/**
 * User Creation Schema
 */
const UserCreateSchema = z.object({
  email: z.string()
    .email("Invalid email address"),
  
  name: z.string()
    .min(2, "Name must be at least 2 characters")
    .max(100, "Name too long"),
  
  password: z.string()
    .min(8, "Password must be at least 8 characters")
    .regex(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/,
      "Password must contain uppercase, lowercase, and number"
    ),
  
  role: z.enum(["user", "admin", "driver"])
    .optional()
    .default("user")
});

/**
 * User Update Schema
 */
const UserUpdateSchema = z.object({
  email: z.string()
    .email()
    .optional(),
  
  name: z.string()
    .min(2)
    .max(100)
    .optional(),
  
  role: z.enum(["user", "admin", "driver"])
    .optional()
}).refine(
  data => Object.keys(data).length > 0,
  "At least one field must be provided for update"
);

/**
 * Shipment Schema
 */
const ShipmentSchema = z.object({
  origin: z.string()
    .min(1, "Origin is required"),
  
  destination: z.string()
    .min(1, "Destination is required"),
  
  weight: z.number()
    .positive("Weight must be positive")
    .optional(),
  
  dimensions: z.object({
    length: z.number().positive(),
    width: z.number().positive(),
    height: z.number().positive(),
    unit: z.enum(["cm", "in"]).default("cm")
  }).optional(),
  
  status: z.enum([
    "pending",
    "in-transit",
    "delivered",
    "cancelled"
  ]).optional().default("pending"),
  
  priority: z.enum(["low", "normal", "high", "urgent"])
    .optional()
    .default("normal")
});

/**
 * Pagination Schema
 */
const PaginationSchema = z.object({
  page: z.string()
    .regex(/^\d+$/)
    .transform(Number)
    .pipe(z.number().int().positive())
    .optional()
    .default("1")
    .transform(String),
  
  limit: z.string()
    .regex(/^\d+$/)
    .transform(Number)
    .pipe(z.number().int().positive().max(100))
    .optional()
    .default("10")
    .transform(String),
  
  sortBy: z.string()
    .optional(),
  
  order: z.enum(["asc", "desc"])
    .optional()
    .default("asc")
});

/**
 * ID Parameter Schema
 */
const IdParamSchema = z.object({
  id: z.string()
    .uuid("Invalid ID format")
});

module.exports = {
  AiCommandSchema,
  AiCommandV2Schema,
  AiBatchCommandSchema,
  AiQuerySchema,
  VoiceProcessingSchema,
  BillingSchema,
  UserCreateSchema,
  UserUpdateSchema,
  ShipmentSchema,
  PaginationSchema,
  IdParamSchema
};

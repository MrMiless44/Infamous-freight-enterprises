import { Router } from "express";
import { body } from "express-validator";
import * as customerController from "../controllers/customer.controller";
import { requireAuth, restrictTo, validate } from "../middleware/validate";

export const customer = Router();

customer.use(requireAuth);

/**
 * @swagger
 * /api/customers:
 *   get:
 *     summary: Get all customers
 *     tags: [Customers]
 */
customer.get(
  "/",
  restrictTo("ADMIN", "DISPATCHER"),
  customerController.getCustomers,
);

/**
 * @swagger
 * /api/customers/{id}:
 *   get:
 *     summary: Get customer by ID
 *     tags: [Customers]
 */
customer.get("/:id", customerController.getCustomerById);

/**
 * @swagger
 * /api/customers/{id}/loads:
 *   get:
 *     summary: Get customer loads
 *     tags: [Customers]
 */
customer.get("/:id/loads", customerController.getCustomerLoads);

/**
 * @swagger
 * /api/customers/support/ai:
 *   post:
 *     summary: Get AI-powered customer support
 *     tags: [Customers]
 */
customer.post(
  "/support/ai",
  [body("question").notEmpty().withMessage("Question is required")],
  validate,
  customerController.getAISupport,
);

const { body, validationResult } = require("express-validator");

/**
 * Middleware to handle validation errors
 */
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const err = new Error("Validation failed");
    err.status = 400;
    err.array = () => errors.array();
    return next(err);
  }
  next();
};

/**
 * Input sanitization validators
 */
const validateEmail = () =>
  body("email").isEmail().normalizeEmail().trim();

const validateString = (field, options = {}) =>
  body(field)
    .isString()
    .trim()
    .notEmpty()
    .withMessage(`${field} is required`)
    .isLength({ min: options.min || 1, max: options.max || 500 })
    .withMessage(`${field} must be between ${options.min || 1} and ${options.max || 500} characters`);

const validatePhone = () =>
  body("phone")
    .optional()
    .isMobilePhone()
    .withMessage("Invalid phone number");

const validateUUID = (field) =>
  body(field).isUUID().withMessage(`${field} must be a valid UUID`);

module.exports = {
  handleValidationErrors,
  validateEmail,
  validateString,
  validatePhone,
  validateUUID,
};

router.METHOD("/path",
  limiters.specific,    // 1. Rate limiting FIRST
  authenticate,         // 2. JWT verification
  requireScope("scope"), // 3. Permission check
  auditLog,            // 4. Audit trail
  [validators...],     // 5. Input validation
  handleValidationErrors, // 6. Validation error handler
  async (req, res, next) => { // 7. Route handler
    // ... logic
  }
);
// CRITICAL: Never break this order!
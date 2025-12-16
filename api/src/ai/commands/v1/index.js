/**
 * AI Commands API v1
 * 
 * Legacy API with circuit breaker protection
 * Status: Maintained for backward compatibility
 * 
 * @version 1.0.0
 * @deprecated Use v2 for new features
 */

const handler = require('./handler');
const { AiCommandSchema } = require('../../../middleware/schemas');

module.exports = {
  handler,
  schema: AiCommandSchema,
  version: '1.0.0',
  deprecated: false,
  features: [
    'circuit-breaker',
    'basic-error-handling',
    'audit-logging'
  ]
};

/**
 * AI Commands API v2
 * 
 * Enhanced API with streaming, batch processing, and improved error handling
 * Status: Active development
 * 
 * @version 2.0.0
 */

const handler = require('./handler');
const streamHandler = require('./streamHandler');
const batchHandler = require('./batchHandler');
const { AiCommandV2Schema, AiBatchCommandSchema } = require('../../../middleware/schemas');

module.exports = {
  handler,
  streamHandler,
  batchHandler,
  schema: AiCommandV2Schema,
  batchSchema: AiBatchCommandSchema,
  version: '2.0.0',
  deprecated: false,
  features: [
    'circuit-breaker',
    'enhanced-error-handling',
    'audit-logging',
    'streaming-support',
    'batch-processing',
    'retry-with-backoff',
    'response-caching'
  ]
};

/**
 * AI Commands v2 Handler
 * 
 * Enhanced command handler with improved error handling,
 * response caching, and detailed metrics.
 */

const { sendCommand, getCircuitBreakerStats } = require('../../aiSyntheticClient');
const { logger } = require('../../../middleware/logger');

/**
 * Process AI command (v2)
 * 
 * @param {object} req - Express request
 * @param {object} res - Express response
 * @param {function} next - Express next middleware
 * @returns {Promise<void>}
 */
async function handleCommand(req, res, next) {
  const {
    command,
    payload = {},
    meta = {},
    options = {}
  } = req.body || {};

  const startTime = Date.now();

  try {
    logger.info('[AI-v2] Processing command', {
      command,
      user: req.user?.sub,
      version: 'v2',
      options
    });

    // Enhanced options for v2
    const enhancedMeta = {
      ...meta,
      user: req.user?.sub,
      version: 'v2',
      requestId: req.id || `req_${Date.now()}`,
      timestamp: new Date().toISOString()
    };

    // Execute command
    const response = await sendCommand(command, payload, enhancedMeta);

    // Calculate duration
    const duration = Date.now() - startTime;

    // Get circuit breaker health
    const circuitHealth = getCircuitBreakerStats();

    // Enhanced response
    res.json({
      ok: true,
      data: response,
      meta: {
        version: 'v2',
        timestamp: new Date().toISOString(),
        duration,
        requestId: enhancedMeta.requestId
      },
      health: {
        circuitBreakers: circuitHealth
      }
    });

    logger.info('[AI-v2] Command completed', {
      command,
      duration,
      user: req.user?.sub
    });

  } catch (err) {
    const duration = Date.now() - startTime;

    logger.error('[AI-v2] Command failed', {
      command,
      error: err.message,
      duration,
      user: req.user?.sub,
      circuitOpen: err.message?.includes('circuit') || err.message?.includes('CIRCUIT')
    });

    // Enhanced error response for v2
    const errorResponse = {
      ok: false,
      error: {
        message: err.message || 'Command execution failed',
        code: err.code || 'COMMAND_ERROR',
        type: err.name || 'Error'
      },
      meta: {
        version: 'v2',
        timestamp: new Date().toISOString(),
        duration,
        requestId: req.id
      }
    };

    // Add circuit breaker info if available
    if (err.message?.includes('CIRCUIT')) {
      errorResponse.error.circuitBreaker = getCircuitBreakerStats();
      errorResponse.error.retryAfter = 30; // seconds
    }

    res.status(err.statusCode || 500).json(errorResponse);
  }
}

module.exports = handleCommand;

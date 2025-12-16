/**
 * AI Commands v1 Handler
 * 
 * Handles AI command execution with circuit breaker protection.
 * This is the stable v1 API maintained for backward compatibility.
 */

const { sendCommand } = require('../../aiSyntheticClient');
const { logger } = require('../../../middleware/logger');

/**
 * Process AI command (v1)
 * 
 * @param {object} req - Express request
 * @param {object} res - Express response
 * @param {function} next - Express next middleware
 * @returns {Promise<void>}
 */
async function handleCommand(req, res, next) {
  const { command, payload = {}, meta = {} } = req.body || {};

  try {
    logger.info('[AI-v1] Processing command', {
      command,
      user: req.user?.sub,
      version: 'v1'
    });

    const response = await sendCommand(command, payload, {
      ...meta,
      user: req.user?.sub,
      version: 'v1'
    });

    res.json({
      ok: true,
      response,
      version: 'v1',
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    logger.error('[AI-v1] Command failed', {
      command,
      error: err.message,
      user: req.user?.sub
    });
    next(err);
  }
}

module.exports = handleCommand;

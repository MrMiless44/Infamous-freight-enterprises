/**
 * AI Commands v2 Stream Handler
 * 
 * Handles streaming AI responses for real-time applications.
 * Uses Server-Sent Events (SSE) for streaming.
 */

const { sendCommand } = require('../../aiSyntheticClient');
const { logger } = require('../../../middleware/logger');

/**
 * Stream AI command response (v2)
 * 
 * @param {object} req - Express request
 * @param {object} res - Express response
 * @param {function} next - Express next middleware
 * @returns {Promise<void>}
 */
async function handleStreamCommand(req, res, next) {
  const { command, payload = {}, meta = {} } = req.body || {};

  try {
    logger.info('[AI-v2-stream] Starting stream', {
      command,
      user: req.user?.sub
    });

    // Set SSE headers
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no'); // Disable nginx buffering

    // Send initial event
    res.write(`event: start\n`);
    res.write(`data: ${JSON.stringify({ 
      status: 'started',
      timestamp: new Date().toISOString()
    })}\n\n`);

    // TODO: Implement actual streaming from AI providers
    // For now, send the complete response as a single chunk
    const response = await sendCommand(command, payload, {
      ...meta,
      user: req.user?.sub,
      version: 'v2',
      stream: true
    });

    // Send data event
    res.write(`event: data\n`);
    res.write(`data: ${JSON.stringify(response)}\n\n`);

    // Send completion event
    res.write(`event: done\n`);
    res.write(`data: ${JSON.stringify({
      status: 'completed',
      timestamp: new Date().toISOString()
    })}\n\n`);

    res.end();

    logger.info('[AI-v2-stream] Stream completed', {
      command,
      user: req.user?.sub
    });

  } catch (err) {
    logger.error('[AI-v2-stream] Stream failed', {
      command,
      error: err.message,
      user: req.user?.sub
    });

    // Send error event
    res.write(`event: error\n`);
    res.write(`data: ${JSON.stringify({
      error: err.message,
      timestamp: new Date().toISOString()
    })}\n\n`);

    res.end();
  }
}

module.exports = handleStreamCommand;

/**
 * AI Commands v2 Batch Handler
 * 
 * Handles batch processing of multiple AI commands.
 * Executes commands in parallel with concurrency control.
 */

const { sendCommand } = require('../../aiSyntheticClient');
const { logger } = require('../../../middleware/logger');

// Maximum concurrent commands
const MAX_CONCURRENCY = parseInt(process.env.AI_BATCH_CONCURRENCY || '5', 10);

/**
 * Execute commands with concurrency limit
 * 
 * @param {Array} commands - Array of commands to execute
 * @param {number} concurrency - Max parallel executions
 * @returns {Promise<Array>} Results array
 */
async function executeBatch(commands, concurrency = MAX_CONCURRENCY) {
  const results = [];
  const executing = [];

  for (const [index, cmd] of commands.entries()) {
    const promise = executeCommand(cmd, index)
      .then(result => {
        results[index] = result;
        executing.splice(executing.indexOf(promise), 1);
        return result;
      });

    results[index] = promise;
    executing.push(promise);

    if (executing.length >= concurrency) {
      await Promise.race(executing);
    }
  }

  await Promise.all(results);
  return results;
}

/**
 * Execute single command
 */
async function executeCommand(cmd, index) {
  const startTime = Date.now();

  try {
    const response = await sendCommand(
      cmd.command,
      cmd.payload || {},
      cmd.meta || {}
    );

    return {
      index,
      ok: true,
      data: response,
      duration: Date.now() - startTime
    };
  } catch (err) {
    return {
      index,
      ok: false,
      error: {
        message: err.message,
        code: err.code || 'COMMAND_ERROR'
      },
      duration: Date.now() - startTime
    };
  }
}

/**
 * Process batch AI commands (v2)
 * 
 * @param {object} req - Express request
 * @param {object} res - Express response
 * @param {function} next - Express next middleware
 * @returns {Promise<void>}
 */
async function handleBatchCommand(req, res, next) {
  const { commands = [], options = {} } = req.body || {};

  const batchStartTime = Date.now();

  try {
    logger.info('[AI-v2-batch] Processing batch', {
      count: commands.length,
      user: req.user?.sub,
      concurrency: options.concurrency || MAX_CONCURRENCY
    });

    // Validate batch size
    const maxBatchSize = parseInt(process.env.AI_MAX_BATCH_SIZE || '10', 10);
    if (commands.length > maxBatchSize) {
      return res.status(400).json({
        ok: false,
        error: {
          message: `Batch size exceeds maximum of ${maxBatchSize}`,
          code: 'BATCH_TOO_LARGE'
        }
      });
    }

    // Execute batch
    const results = await executeBatch(
      commands,
      options.concurrency || MAX_CONCURRENCY
    );

    const batchDuration = Date.now() - batchStartTime;

    // Calculate statistics
    const stats = {
      total: results.length,
      successful: results.filter(r => r.ok).length,
      failed: results.filter(r => !r.ok).length,
      avgDuration: Math.round(
        results.reduce((sum, r) => sum + r.duration, 0) / results.length
      )
    };

    res.json({
      ok: true,
      data: results,
      meta: {
        version: 'v2',
        timestamp: new Date().toISOString(),
        batchDuration,
        stats
      }
    });

    logger.info('[AI-v2-batch] Batch completed', {
      ...stats,
      batchDuration,
      user: req.user?.sub
    });

  } catch (err) {
    const batchDuration = Date.now() - batchStartTime;

    logger.error('[AI-v2-batch] Batch failed', {
      error: err.message,
      batchDuration,
      user: req.user?.sub
    });

    next(err);
  }
}

module.exports = handleBatchCommand;

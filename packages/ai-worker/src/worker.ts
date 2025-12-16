import { Queue, Worker, QueueEvents, JobsOptions, MetricsTime } from 'bullmq';
import Redis from 'ioredis';
import { sendAICommand } from '@infamous-freight/shared/aiClient';

const REDIS_URL = process.env.REDIS_URL || process.env.REDIS_CONNECTION_STRING || 'redis://localhost:6379';
const QUEUE_NAME = process.env.AI_QUEUE_NAME || 'ai-commands';

// Redis connections
const connection = new Redis(REDIS_URL, {
  maxRetriesPerRequest: null,
  enableReadyCheck: true,
});

const queue = new Queue(QUEUE_NAME, { connection });
const queueEvents = new QueueEvents(QUEUE_NAME, { connection });

// Optional: expose minimal runtime logs
queueEvents.on('waiting', ({ jobId }) => {
  console.log(`[ai-worker] Job waiting: ${jobId}`);
});
queueEvents.on('active', ({ jobId }) => {
  console.log(`[ai-worker] Job active: ${jobId}`);
});
queueEvents.on('completed', ({ jobId }) => {
  console.log(`[ai-worker] Job completed: ${jobId}`);
});
queueEvents.on('failed', ({ jobId, failedReason }) => {
  console.error(`[ai-worker] Job failed: ${jobId} - ${failedReason}`);
});

// Worker processor
const worker = new Worker(
  QUEUE_NAME,
  async (job) => {
    const start = Date.now();

    // Job payload shape: { command: string, payload: any }
    const { command, payload } = job.data || {};
    if (!command) {
      throw new Error('Missing command in job data');
    }

    try {
      const result = await sendAICommand(command, payload);
      const durationMs = Date.now() - start;
      console.log(`[ai-worker] Job ${job.id} success in ${durationMs}ms`);
      return result;
    } catch (err: any) {
      const durationMs = Date.now() - start;
      console.error(`[ai-worker] Job ${job.id} error in ${durationMs}ms: ${err?.message}`);
      throw err;
    }
  },
  { connection, metrics: { maxDataPoints: MetricsTime.ONE_WEEK } }
);

worker.on('completed', (job) => {
  console.log(`[ai-worker] Processed job ${job.id}`);
});
worker.on('failed', (job, err) => {
  console.error(`[ai-worker] Failed job ${job?.id}:`, err?.message);
});

// Graceful shutdown
const shutdown = async () => {
  console.log('[ai-worker] Shutting down...');
  await worker.close();
  await queue.close();
  await queueEvents.close();
  await connection.quit();
  process.exit(0);
};

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

// Optional: simple enqueue helper when launched with ENQUEUE_SAMPLE=true
(async () => {
  if (process.env.ENQUEUE_SAMPLE === 'true') {
    const jobOpts: JobsOptions = { removeOnComplete: true, removeOnFail: 100 };
    await queue.add('sample', { command: 'echo', payload: { text: 'Hello from worker' } }, jobOpts);
    console.log('[ai-worker] Enqueued sample job');
  }

  console.log(`[ai-worker] Listening on queue: ${QUEUE_NAME} (Redis: ${REDIS_URL})`);
})();

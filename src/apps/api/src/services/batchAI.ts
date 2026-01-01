/**
 * Batch AI Processing Service
 * Processes multiple invoices in parallel
 * Expected: 10x throughput (500 invoices in 30s vs 5 minutes)
 */

import type { AiDecision } from "@infamous-freight/shared";

interface Invoice {
  id: string;
  organizationId: string;
  amount: number;
  vendor: string;
  description: string;
  dueDate: Date;
}

interface BatchResult {
  processed: number;
  succeeded: number;
  failed: number;
  duration: number;
  decisions: AiDecision[];
  errors: Array<{ invoiceId: string; error: string }>;
}

/**
 * Process invoices in batches
 */
export async function processBatch(
  invoices: Invoice[],
  aiClient: any,
  batchSize: number = 50,
): Promise<BatchResult> {
  const startTime = Date.now();
  const results: AiDecision[] = [];
  const errors: Array<{ invoiceId: string; error: string }> = [];

  console.log(
    `🤖 Starting batch processing: ${invoices.length} invoices (batch size: ${batchSize})`,
  );

  for (let i = 0; i < invoices.length; i += batchSize) {
    const batch = invoices.slice(i, i + batchSize);
    console.log(
      `Processing batch ${Math.floor(i / batchSize) + 1}/${Math.ceil(invoices.length / batchSize)}`,
    );

    // Process batch in parallel
    const batchPromises = batch.map(async (invoice) => {
      try {
        const decision = await aiClient.makeDecision(invoice);
        return { success: true, decision };
      } catch (error: any) {
        return {
          success: false,
          invoiceId: invoice.id,
          error: error.message,
        };
      }
    });

    const batchResults = await Promise.allSettled(batchPromises);

    // Collect results
    batchResults.forEach((result, idx) => {
      if (result.status === "fulfilled") {
        if (result.value.success) {
          results.push(result.value.decision);
        } else {
          errors.push({
            invoiceId: result.value.invoiceId,
            error: result.value.error,
          });
        }
      } else {
        errors.push({
          invoiceId: batch[idx].id,
          error: result.reason?.message || "Unknown error",
        });
      }
    });

    // Rate limiting delay between batches
    if (i + batchSize < invoices.length) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }

  const duration = Date.now() - startTime;

  console.log(`✅ Batch processing complete:
    - Total: ${invoices.length}
    - Succeeded: ${results.length}
    - Failed: ${errors.length}
    - Duration: ${(duration / 1000).toFixed(2)}s
    - Throughput: ${(invoices.length / (duration / 1000)).toFixed(1)} invoices/sec
  `);

  return {
    processed: invoices.length,
    succeeded: results.length,
    failed: errors.length,
    duration,
    decisions: results,
    errors,
  };
}

/**
 * Priority-based batch processing
 * High-priority invoices processed first
 */
export async function processPriorityBatch(
  invoices: Invoice[],
  aiClient: any,
  getPriority: (invoice: Invoice) => number = (inv) => inv.amount,
): Promise<BatchResult> {
  // Sort by priority (descending)
  const sorted = [...invoices].sort((a, b) => getPriority(b) - getPriority(a));

  return processBatch(sorted, aiClient);
}

/**
 * Batch processing with retry logic
 */
export async function processBatchWithRetry(
  invoices: Invoice[],
  aiClient: any,
  maxRetries: number = 3,
): Promise<BatchResult> {
  let attempt = 0;
  let result: BatchResult;

  while (attempt < maxRetries) {
    result = await processBatch(invoices, aiClient);

    if (result.errors.length === 0) {
      return result;
    }

    // Retry failed invoices
    const failedInvoices = result.errors
      .map((err) => invoices.find((inv) => inv.id === err.invoiceId))
      .filter(Boolean) as Invoice[];

    if (failedInvoices.length === 0 || attempt === maxRetries - 1) {
      return result;
    }

    attempt++;
    console.log(
      `⚠️  Retrying ${failedInvoices.length} failed invoices (attempt ${attempt}/${maxRetries})`,
    );

    // Exponential backoff
    await new Promise((resolve) =>
      setTimeout(resolve, Math.pow(2, attempt) * 1000),
    );

    invoices = failedInvoices;
  }

  return result!;
}

/**
 * Streaming batch processor
 * Yields results as they complete (for real-time updates)
 */
export async function* streamBatchProcess(
  invoices: Invoice[],
  aiClient: any,
  batchSize: number = 50,
): AsyncGenerator<{ decision: AiDecision; progress: number }, void, unknown> {
  let processed = 0;

  for (let i = 0; i < invoices.length; i += batchSize) {
    const batch = invoices.slice(i, i + batchSize);

    const batchPromises = batch.map(async (invoice) => {
      const decision = await aiClient.makeDecision(invoice);
      return decision;
    });

    const decisions = await Promise.all(batchPromises);

    for (const decision of decisions) {
      processed++;
      yield {
        decision,
        progress: (processed / invoices.length) * 100,
      };
    }
  }
}

export default {
  processBatch,
  processPriorityBatch,
  processBatchWithRetry,
  streamBatchProcess,
};

/**
 * Rate Limiting Load Test
 * Tests rate limiting enforcement under sustained load
 */

import axios from "axios";
import { performance } from "perf_hooks";

interface LoadTestResult {
  endpoint: string;
  totalRequests: number;
  successfulRequests: number;
  throttledRequests: number;
  errorRequests: number;
  averageResponseTime: number;
  minResponseTime: number;
  maxResponseTime: number;
  requestsPerSecond: number;
  duration: number;
}

interface LoadTestConfig {
  endpoint: string;
  method?: "GET" | "POST" | "PATCH" | "DELETE";
  requestsPerSecond?: number;
  durationSeconds?: number;
  headers?: Record<string, string>;
  data?: any;
}

/**
 * Execute load test
 */
export async function runLoadTest(
  config: LoadTestConfig,
): Promise<LoadTestResult> {
  const {
    endpoint,
    method = "GET",
    requestsPerSecond = 10,
    durationSeconds = 60,
    headers = {},
    data,
  } = config;

  const results = {
    endpoint,
    totalRequests: 0,
    successfulRequests: 0,
    throttledRequests: 0,
    errorRequests: 0,
    responseTimes: [] as number[],
    startTime: performance.now(),
    duration: 0,
  };

  const totalRequestsTarget = requestsPerSecond * durationSeconds;
  const delayBetweenRequests = 1000 / requestsPerSecond;

  console.log(`\n🔥 Load Test Starting`);
  console.log(`   Endpoint: ${endpoint}`);
  console.log(`   RPS: ${requestsPerSecond}`);
  console.log(`   Duration: ${durationSeconds}s`);
  console.log(`   Total Requests: ${totalRequestsTarget}`);
  console.log(`   ========================\n`);

  let lastRequestTime = 0;

  for (let i = 0; i < totalRequestsTarget; i++) {
    const now = performance.now();

    // Throttle requests to match RPS
    if (i > 0) {
      const timeSinceLastRequest = now - lastRequestTime;
      if (timeSinceLastRequest < delayBetweenRequests) {
        await sleep(delayBetweenRequests - timeSinceLastRequest);
      }
    }

    lastRequestTime = performance.now();

    try {
      const reqStartTime = performance.now();

      const response = await axios({
        method,
        url: endpoint,
        headers,
        data,
        timeout: 5000,
        validateStatus: () => true, // Don't throw on any status
      });

      const responseTime = performance.now() - reqStartTime;
      results.responseTimes.push(responseTime);

      results.totalRequests++;

      if (response.status === 429) {
        results.throttledRequests++;
      } else if (response.status >= 200 && response.status < 300) {
        results.successfulRequests++;
      } else if (response.status >= 400) {
        results.errorRequests++;
      }

      // Log progress every 10%
      if ((i + 1) % Math.ceil(totalRequestsTarget / 10) === 0) {
        const progress = Math.round(((i + 1) / totalRequestsTarget) * 100);
        console.log(
          `   ${progress}% - ${i + 1}/${totalRequestsTarget} requests`,
        );
      }
    } catch (error) {
      results.errorRequests++;
      results.totalRequests++;
    }
  }

  results.duration = (performance.now() - results.startTime) / 1000;

  // Calculate statistics
  const responseTimes = results.responseTimes;
  const avgResponseTime =
    responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length;
  const minResponseTime = Math.min(...responseTimes);
  const maxResponseTime = Math.max(...responseTimes);
  const actualRPS = results.totalRequests / results.duration;

  return {
    endpoint,
    totalRequests: results.totalRequests,
    successfulRequests: results.successfulRequests,
    throttledRequests: results.throttledRequests,
    errorRequests: results.errorRequests,
    averageResponseTime: Math.round(avgResponseTime * 100) / 100,
    minResponseTime: Math.round(minResponseTime * 100) / 100,
    maxResponseTime: Math.round(maxResponseTime * 100) / 100,
    requestsPerSecond: Math.round(actualRPS * 100) / 100,
    duration: Math.round(results.duration * 100) / 100,
  };
}

/**
 * Run multiple load tests
 */
export async function runLoadTestSuite(
  tests: LoadTestConfig[],
): Promise<LoadTestResult[]> {
  const results: LoadTestResult[] = [];

  for (const test of tests) {
    const result = await runLoadTest(test);
    results.push(result);

    console.log(`\n✅ Test Complete: ${test.endpoint}`);
    printLoadTestResults(result);

    // Wait between tests
    await sleep(2000);
  }

  return results;
}

/**
 * Print load test results
 */
function printLoadTestResults(result: LoadTestResult) {
  console.log(`
📊 Results for ${result.endpoint}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total Requests:       ${result.totalRequests}
✅ Successful:        ${result.successfulRequests} (${((result.successfulRequests / result.totalRequests) * 100).toFixed(1)}%)
⏱️  Throttled (429):   ${result.throttledRequests} (${((result.throttledRequests / result.totalRequests) * 100).toFixed(1)}%)
❌ Errors:            ${result.errorRequests} (${((result.errorRequests / result.totalRequests) * 100).toFixed(1)}%)

Response Times:
├─ Average:          ${result.averageResponseTime}ms
├─ Min:              ${result.minResponseTime}ms
└─ Max:              ${result.maxResponseTime}ms

Throughput:
├─ Target RPS:       (from config)
├─ Actual RPS:       ${result.requestsPerSecond}
└─ Duration:         ${result.duration}s
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  `);
}

/**
 * Analyze rate limit compliance
 */
export function analyzeRateLimitCompliance(result: LoadTestResult): {
  compliant: boolean;
  violations: string[];
} {
  const violations: string[] = [];

  // Rate limiter should throttle some requests at high load
  if (result.throttledRequests === 0 && result.requestsPerSecond > 5) {
    violations.push("Expected some requests to be throttled at high load");
  }

  // Response times should be reasonable even under load
  if (result.maxResponseTime > 5000) {
    violations.push(`Max response time too high: ${result.maxResponseTime}ms`);
  }

  // Error rate should be low
  const errorRate = result.errorRequests / result.totalRequests;
  if (errorRate > 0.05) {
    violations.push(`Error rate too high: ${(errorRate * 100).toFixed(1)}%`);
  }

  return {
    compliant: violations.length === 0,
    violations,
  };
}

/**
 * Sleep utility
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Example usage and test suite
 */
export async function exampleRateLimitingTests() {
  const baseUrl = process.env.API_URL || "http://localhost:4000";
  const token = process.env.TEST_TOKEN || "test-token";

  const tests: LoadTestConfig[] = [
    {
      endpoint: `${baseUrl}/api/health`,
      method: "GET",
      requestsPerSecond: 50, // Should handle 50 RPS
      durationSeconds: 30,
    },
    {
      endpoint: `${baseUrl}/api/shipments`,
      method: "GET",
      requestsPerSecond: 10, // Should handle 10 RPS
      durationSeconds: 30,
      headers: {
        Authorization: `Bearer ${token}`,
      },
    },
    {
      endpoint: `${baseUrl}/api/auth/login`,
      method: "POST",
      requestsPerSecond: 5, // Should limit login attempts
      durationSeconds: 30,
      headers: {
        "Content-Type": "application/json",
      },
      data: {
        email: "test@example.com",
        password: "password123",
      },
    },
  ];

  const results = await runLoadTestSuite(tests);

  // Analyze results
  console.log("\n\n📈 COMPLIANCE ANALYSIS\n");
  for (const result of results) {
    const analysis = analyzeRateLimitCompliance(result);
    console.log(`\n${result.endpoint}`);
    if (analysis.compliant) {
      console.log("✅ COMPLIANT: Rate limiting working as expected");
    } else {
      console.log("⚠️  VIOLATIONS:");
      analysis.violations.forEach((v) => console.log(`   - ${v}`));
    }
  }

  return results;
}

// Export for testing
export default {
  runLoadTest,
  runLoadTestSuite,
  analyzeRateLimitCompliance,
  exampleRateLimitingTests,
};

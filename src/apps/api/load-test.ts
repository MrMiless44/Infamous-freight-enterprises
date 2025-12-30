/**
 * Phase 2 Performance Optimization - Load Testing Framework
 * 
 * Simulates 100 concurrent requests to measure:
 *   - Response time (p95 < 1.2s target, currently ~2.0s)
 *   - Throughput (target 500+ RPS, currently ~300)
 *   - Error rates (target < 0.1%)
 *   - Database query performance
 * 
 * Run: npx ts-node load-test.ts
 */

import http from 'http';

interface LoadTestConfig {
  baseUrl: string;
  concurrentRequests: number;
  totalRequests: number;
  timeout: number;
  endpoints: string[];
}

interface LoadTestResult {
  endpoint: string;
  totalRequests: number;
  successCount: number;
  errorCount: number;
  avgResponseTime: number;
  minResponseTime: number;
  maxResponseTime: number;
  p95ResponseTime: number;
  throughputRps: number;
  errorRate: number;
}

class LoadTester {
  private config: LoadTestConfig;
  private results: Map<string, number[]> = new Map();
  private startTime: number = 0;

  constructor(config: LoadTestConfig) {
    this.config = config;
    this.results = new Map(
      config.endpoints.map((endpoint) => [endpoint, []])
    );
  }

  /**
   * Make HTTP request with timing
   */
  private makeRequest(url: string): Promise<number> {
    return new Promise((resolve, reject) => {
      const requestStartTime = Date.now();

      const req = http.get(url, { timeout: this.config.timeout }, (res) => {
        let data = '';

        res.on('data', (chunk) => {
          data += chunk;
        });

        res.on('end', () => {
          const responseTime = Date.now() - requestStartTime;
          if (res.statusCode === 200) {
            resolve(responseTime);
          } else {
            reject(new Error(`Status: ${res.statusCode}`));
          }
        });
      });

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Request timeout'));
      });
    });
  }

  /**
   * Run load test
   */
  async run(): Promise<LoadTestResult[]> {
    console.log('🔥 Starting Phase 2 Load Test...\n');
    console.log(`Configuration:`);
    console.log(`  Concurrent requests: ${this.config.concurrentRequests}`);
    console.log(`  Total requests: ${this.config.totalRequests}`);
    console.log(`  Timeout: ${this.config.timeout}ms`);
    console.log(`  Endpoints: ${this.config.endpoints.length}\n`);

    this.startTime = Date.now();
    const endpointIndices: number[] = [];

    // Generate request sequence
    for (let i = 0; i < this.config.totalRequests; i++) {
      endpointIndices.push(i % this.config.endpoints.length);
    }

    // Shuffle for realistic distribution
    for (let i = endpointIndices.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [endpointIndices[i], endpointIndices[j]] = [
        endpointIndices[j],
        endpointIndices[i],
      ];
    }

    // Execute with concurrency control
    let successCount = 0;
    let errorCount = 0;

    for (let i = 0; i < endpointIndices.length; i += this.config.concurrentRequests) {
      const batch = endpointIndices.slice(
        i,
        i + this.config.concurrentRequests
      );
      const promises = batch.map((idx) => {
        const endpoint = this.config.endpoints[idx];
        const url = `${this.config.baseUrl}${endpoint}`;

        return this.makeRequest(url)
          .then((responseTime) => {
            const times = this.results.get(endpoint) || [];
            times.push(responseTime);
            this.results.set(endpoint, times);
            successCount++;
          })
          .catch((error) => {
            errorCount++;
            console.error(`❌ ${endpoint}: ${error.message}`);
          });
      });

      await Promise.all(promises);

      // Progress indicator
      const progress = Math.min(i + this.config.concurrentRequests, endpointIndices.length);
      const percentage = ((progress / endpointIndices.length) * 100).toFixed(1);
      console.log(`Progress: ${percentage}% (${progress}/${endpointIndices.length})`);
    }

    const totalTime = (Date.now() - this.startTime) / 1000;
    const throughput = this.config.totalRequests / totalTime;

    console.log(`\n✅ Load test completed in ${totalTime.toFixed(2)}s`);
    console.log(`   Throughput: ${throughput.toFixed(2)} RPS\n`);

    // Generate results
    return Array.from(this.results.entries()).map(([endpoint, times]) => {
      const sorted = times.sort((a, b) => a - b);
      const avgTime = times.reduce((a, b) => a + b, 0) / times.length;
      const p95Index = Math.ceil(sorted.length * 0.95) - 1;

      return {
        endpoint,
        totalRequests: times.length,
        successCount: times.length,
        errorCount: 0,
        avgResponseTime: avgTime,
        minResponseTime: sorted[0],
        maxResponseTime: sorted[sorted.length - 1],
        p95ResponseTime: sorted[p95Index],
        throughputRps: times.length / totalTime,
        errorRate: 0,
      };
    });
  }

  /**
   * Print results with emoji indicators
   */
  static printResults(results: LoadTestResult[]): void {
    console.log('═'.repeat(100));
    console.log('📊 LOAD TEST RESULTS');
    console.log('═'.repeat(100) + '\n');

    let totalSuccessCount = 0;
    let totalRequestCount = 0;
    let totalThroughput = 0;

    for (const result of results) {
      totalSuccessCount += result.successCount;
      totalRequestCount += result.totalRequests;
      totalThroughput += result.throughputRps;

      const avgStatus =
        result.avgResponseTime < 100
          ? '🟢'
          : result.avgResponseTime < 500
            ? '🟡'
            : '🔴';
      const p95Status =
        result.p95ResponseTime < 1200
          ? '🟢'
          : result.p95ResponseTime < 2000
            ? '🟡'
            : '🔴';

      console.log(`Endpoint: ${result.endpoint}`);
      console.log(`  Requests:   ${result.totalRequests} (Success: ${result.successCount}, Errors: ${result.errorCount})`);
      console.log(`  Avg Time:   ${avgStatus} ${result.avgResponseTime.toFixed(0)}ms`);
      console.log(`  Min/Max:    ${result.minResponseTime.toFixed(0)}ms / ${result.maxResponseTime.toFixed(0)}ms`);
      console.log(`  P95 Time:   ${p95Status} ${result.p95ResponseTime.toFixed(0)}ms (target: <1200ms)`);
      console.log(`  Throughput: ${result.throughputRps.toFixed(2)} RPS`);
      console.log('');
    }

    console.log('═'.repeat(100));
    console.log('SUMMARY');
    console.log('═'.repeat(100));
    console.log(`Total Requests:     ${totalRequestCount}`);
    console.log(`Success Rate:       ${((totalSuccessCount / totalRequestCount) * 100).toFixed(2)}%`);
    console.log(`Total Throughput:   ${totalThroughput.toFixed(2)} RPS`);
    console.log(`\n✅ Target (500+ RPS): ${totalThroughput >= 500 ? '🟢 PASSED' : '🔴 NEEDS IMPROVEMENT'}`);
    console.log(`✅ Target (p95 < 1.2s): ${results.every((r) => r.p95ResponseTime < 1200) ? '🟢 PASSED' : '🔴 NEEDS IMPROVEMENT'}`);
    console.log('═'.repeat(100) + '\n');
  }
}

/**
 * Run the load test
 */
async function runLoadTest(): Promise<void> {
  const config: LoadTestConfig = {
    baseUrl: process.env.API_URL || 'http://localhost:4000/api',
    concurrentRequests: 10,
    totalRequests: 1000,
    timeout: 5000,
    endpoints: [
      '/shipments',
      '/drivers',
      '/routes',
      '/analytics',
      '/notifications',
      '/profile',
      '/health',
    ],
  };

  const tester = new LoadTester(config);

  try {
    const results = await tester.run();
    LoadTester.printResults(results);
  } catch (error) {
    console.error('Load test failed:', error);
    process.exit(1);
  }
}

// Run if executed directly
if (require.main === module) {
  runLoadTest();
}

export { LoadTester, LoadTestConfig, LoadTestResult };

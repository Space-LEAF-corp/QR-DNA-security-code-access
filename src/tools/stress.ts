/**
 * Stress Test Harness for Fox QPPI
 */

import { initializeFox } from '../index.js';
import type { StressTestConfig, StressTestResult } from '../core/Types.js';
import { writeFileSync } from 'fs';
import { join } from 'path';

export class StressTestHarness {
  private config: StressTestConfig;

  constructor(config?: Partial<StressTestConfig>) {
    this.config = {
      durationSeconds: parseInt(process.env.STRESS_DURATION_SECONDS || '60'),
      concurrentRequests: parseInt(process.env.STRESS_CONCURRENT_REQUESTS || '10'),
      s3Bucket: process.env.STRESS_S3_BUCKET,
      s3Region: process.env.STRESS_S3_REGION || 'us-east-1',
      ...config,
    };
  }

  /**
   * Run stress test
   */
  async run(): Promise<StressTestResult> {
    console.log('Starting Fox QPPI Stress Test...');
    console.log(`Duration: ${this.config.durationSeconds}s`);
    console.log(`Concurrent requests: ${this.config.concurrentRequests}`);

    const fox = initializeFox();
    const startTime = Date.now();
    const endTime = startTime + this.config.durationSeconds * 1000;

    let totalRequests = 0;
    let successfulRequests = 0;
    let failedRequests = 0;
    const responseTimes: number[] = [];

    // Generate test events
    const testEvents = this.generateTestEvents();

    // Run concurrent workers
    const workers: Promise<void>[] = [];
    
    for (let i = 0; i < this.config.concurrentRequests; i++) {
      workers.push(
        this.runWorker(i, fox, testEvents, endTime, (success, responseTime) => {
          totalRequests++;
          if (success) {
            successfulRequests++;
          } else {
            failedRequests++;
          }
          responseTimes.push(responseTime);
        })
      );
    }

    await Promise.all(workers);

    const result: StressTestResult = {
      totalRequests,
      successfulRequests,
      failedRequests,
      averageResponseTime: this.calculateAverage(responseTimes),
      minResponseTime: Math.min(...responseTimes),
      maxResponseTime: Math.max(...responseTimes),
      startTime,
      endTime: Date.now(),
    };

    console.log('\nStress Test Results:');
    console.log(`Total Requests: ${result.totalRequests}`);
    console.log(`Successful: ${result.successfulRequests}`);
    console.log(`Failed: ${result.failedRequests}`);
    console.log(`Average Response Time: ${result.averageResponseTime.toFixed(2)}ms`);
    console.log(`Min Response Time: ${result.minResponseTime.toFixed(2)}ms`);
    console.log(`Max Response Time: ${result.maxResponseTime.toFixed(2)}ms`);
    console.log(`Ledger Integrity: ${fox.verifyLedgerIntegrity() ? 'VALID' : 'INVALID'}`);

    // Save results
    await this.saveResults(result);

    return result;
  }

  /**
   * Run a single worker
   */
  private async runWorker(
    workerId: number,
    fox: any,
    events: Record<string, unknown>[],
    endTime: number,
    callback: (success: boolean, responseTime: number) => void
  ): Promise<void> {
    let eventIndex = 0;

    while (Date.now() < endTime) {
      const event = events[eventIndex % events.length];
      eventIndex++;

      const startRequest = Date.now();
      
      try {
        await fox.processEvent({
          ...event,
          workerId,
          requestId: `${workerId}-${eventIndex}`,
        });
        
        const responseTime = Date.now() - startRequest;
        callback(true, responseTime);
      } catch (error) {
        const responseTime = Date.now() - startRequest;
        callback(false, responseTime);
        console.error(`Worker ${workerId} error:`, error);
      }

      // Small delay to prevent overwhelming
      await this.sleep(10);
    }
  }

  /**
   * Generate test events
   */
  private generateTestEvents(): Record<string, unknown>[] {
    const userIds = Array.from({ length: 100 }, (_, i) => `user${i}`);
    const actions = [
      'login',
      'logout',
      'access_attempt',
      'data_access',
      'settings_change',
      'password_change',
      'session_time',
    ];

    const events: Record<string, unknown>[] = [];

    for (let i = 0; i < 50; i++) {
      events.push({
        userId: userIds[Math.floor(Math.random() * userIds.length)],
        action: actions[Math.floor(Math.random() * actions.length)],
        timestamp: Date.now(),
        age: Math.random() > 0.8 ? Math.floor(Math.random() * 70) : undefined,
        sessionMinutes: Math.random() > 0.7 ? Math.floor(Math.random() * 200) : undefined,
      });
    }

    return events;
  }

  /**
   * Calculate average
   */
  private calculateAverage(numbers: number[]): number {
    if (numbers.length === 0) return 0;
    return numbers.reduce((a, b) => a + b, 0) / numbers.length;
  }

  /**
   * Sleep utility
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Save results to file and optionally S3
   */
  private async saveResults(result: StressTestResult): Promise<void> {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `stress-test-${timestamp}.json`;
    
    // Save locally
    const localPath = join(process.cwd(), 'stress-test-results', filename);
    try {
      const { mkdirSync } = await import('fs');
      mkdirSync(join(process.cwd(), 'stress-test-results'), { recursive: true });
      writeFileSync(localPath, JSON.stringify(result, null, 2));
      console.log(`\nResults saved to: ${localPath}`);
    } catch (error) {
      console.error('Error saving results locally:', error);
    }

    // Upload to S3 if configured
    if (this.config.s3Bucket) {
      console.log(`\nS3 upload would go to: ${this.config.s3Bucket}/${filename}`);
      console.log('(S3 upload implementation depends on AWS SDK configuration)');
    }
  }
}

/**
 * Main execution when run directly
 */
if (import.meta.url === `file://${process.argv[1]}`) {
  const harness = new StressTestHarness();
  
  harness.run()
    .then(() => {
      console.log('\nStress test completed successfully');
      process.exit(0);
    })
    .catch(error => {
      console.error('Stress test failed:', error);
      process.exit(1);
    });
}

/**
 * Stress testing harness for Fox QPPI
 */

import type { StressTestConfig, StressTestResult } from '../core/Types.js';
import { KeyManager } from '../security/keyManager.js';
import { QrDnaAuth } from '../security/qrDnaAuth.js';
import { ImmutableLedger } from '../security/immutableLedger.js';

async function runOperation(_name: string, operation: () => Promise<void>): Promise<{ success: boolean; error?: string }> {
  try {
    await operation();
    return { success: true };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    };
  }
}

export async function runStressTest(config: StressTestConfig): Promise<StressTestResult> {
  const startTime = Date.now();
  const results: StressTestResult = {
    totalOperations: 0,
    successfulOperations: 0,
    failedOperations: 0,
    durationMs: 0,
    operationsPerSecond: 0,
    errors: []
  };

  // Initialize components
  const keyManager = new KeyManager();
  const auth = new QrDnaAuth({ useKms: false });
  const ledger = new ImmutableLedger();

  // Generate test keys
  const testKeys = Array.from({ length: 10 }, () => keyManager.generateKey());
  
  console.log('🔥 Starting stress test...');
  console.log(`   Duration: ${config.durationMs}ms`);
  console.log(`   Concurrency: ${config.concurrency}`);
  console.log(`   Operations: ${config.operations.join(', ')}`);

  const endTime = startTime + config.durationMs;
  const workers: Promise<void>[] = [];

  for (let i = 0; i < config.concurrency; i++) {
    workers.push((async () => {
      while (Date.now() < endTime) {
        for (const op of config.operations) {
          results.totalOperations++;

          let result;
          switch (op) {
            case 'generate_key':
              result = await runOperation(op, async () => {
                keyManager.generateKey();
              });
              break;

            case 'create_token':
              result = await runOperation(op, async () => {
                const key = testKeys[Math.floor(Math.random() * testKeys.length)];
                auth.createToken(key.keyId);
              });
              break;

            case 'verify_token':
              result = await runOperation(op, async () => {
                const key = testKeys[Math.floor(Math.random() * testKeys.length)];
                const token = auth.createToken(key.keyId);
                await auth.verifyToken(token);
              });
              break;

            case 'ledger_append':
              result = await runOperation(op, async () => {
                await ledger.append({
                  action: 'stress_test',
                  data: { iteration: results.totalOperations }
                });
              });
              break;

            case 'ledger_verify':
              result = await runOperation(op, async () => {
                ledger.verify();
              });
              break;

            default:
              result = { success: false, error: `Unknown operation: ${op}` };
          }

          if (result.success) {
            results.successfulOperations++;
          } else {
            results.failedOperations++;
            if (result.error) {
              results.errors.push({ operation: op, error: result.error });
            }
          }
        }
      }
    })());
  }

  await Promise.all(workers);

  results.durationMs = Date.now() - startTime;
  results.operationsPerSecond = (results.totalOperations / results.durationMs) * 1000;

  console.log('\n📊 Stress test results:');
  console.log(`   Total operations: ${results.totalOperations}`);
  console.log(`   Successful: ${results.successfulOperations}`);
  console.log(`   Failed: ${results.failedOperations}`);
  console.log(`   Duration: ${results.durationMs}ms`);
  console.log(`   Operations/sec: ${results.operationsPerSecond.toFixed(2)}`);
  console.log(`   Error count: ${results.errors.length}`);

  return results;
}

// CLI execution
if (import.meta.url === `file://${process.argv[1]}`) {
  const config: StressTestConfig = {
    durationMs: Number(process.env.STRESS_DURATION_MS) || 60000,
    concurrency: Number(process.env.STRESS_CONCURRENCY) || 10,
    operations: ['generate_key', 'create_token', 'verify_token', 'ledger_append', 'ledger_verify']
  };

  runStressTest(config)
    .then(results => {
      console.log('\n✅ Stress test complete');
      process.exit(results.failedOperations > 0 ? 1 : 0);
    })
    .catch(error => {
      console.error('\n❌ Stress test failed:', error);
      process.exit(1);
    });
}

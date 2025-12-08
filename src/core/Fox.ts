/**
 * Fox - Main orchestrator for QR-DNA operations
 */

import type { FoxConfig, TailConfig, QrDnaToken, VerificationResult } from './Types.js';
import { Tail } from './Tail.js';
import { verifyWithRegistry } from '../security/verifyWithRegistry.js';
import { ImmutableLedger } from '../security/immutableLedger.js';
import { Monitoring } from '../security/monitoring.js';

export class Fox {
  private config: FoxConfig;
  private tails: Map<string, Tail>;
  private ledger: ImmutableLedger;
  private monitoring: Monitoring;

  constructor(config: FoxConfig) {
    this.config = config;
    this.tails = new Map();
    this.ledger = new ImmutableLedger();
    this.monitoring = new Monitoring(config.monitoring);
    this.initializeTails();
  }

  private initializeTails(): void {
    for (const tailConfig of this.config.tails) {
      if (tailConfig.enabled) {
        const tail = new Tail(tailConfig);
        this.tails.set(tailConfig.name, tail);
      }
    }
  }

  async start(): Promise<void> {
    console.log('🦊 Fox QPPI starting...');
    
    // Start all enabled tails
    for (const [name, tail] of this.tails) {
      await tail.start();
      console.log(`  ✓ Tail "${name}" started`);
    }

    // Start monitoring
    if (this.config.monitoring.enabled) {
      await this.monitoring.start();
      console.log('  ✓ Monitoring started');
    }

    console.log('🦊 Fox QPPI ready');
  }

  async stop(): Promise<void> {
    console.log('🦊 Fox QPPI stopping...');
    
    // Stop all tails
    for (const [name, tail] of this.tails) {
      await tail.stop();
      console.log(`  ✓ Tail "${name}" stopped`);
    }

    // Stop monitoring
    if (this.config.monitoring.enabled) {
      await this.monitoring.stop();
      console.log('  ✓ Monitoring stopped');
    }

    console.log('🦊 Fox QPPI stopped');
  }

  async verifyToken(token: QrDnaToken): Promise<VerificationResult> {
    try {
      // Record attempt in ledger
      await this.ledger.append({
        action: 'verify_token',
        data: { tokenId: token.id }
      });

      // Verify with registry
      const result = await verifyWithRegistry(token);

      // Record result
      await this.ledger.append({
        action: 'verification_result',
        data: { tokenId: token.id, valid: result.valid }
      });

      // Track metrics
      this.monitoring.recordVerification(result.valid);

      return result;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      this.monitoring.recordError('verification_failed', errorMessage);
      
      return {
        valid: false,
        error: errorMessage,
        timestamp: Date.now()
      };
    }
  }

  async getLedger(): Promise<ImmutableLedger> {
    return this.ledger;
  }

  getTail(name: string): Tail | undefined {
    return this.tails.get(name);
  }

  getMonitoring(): Monitoring {
    return this.monitoring;
  }
}

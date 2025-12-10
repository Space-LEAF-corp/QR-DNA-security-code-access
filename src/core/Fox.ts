/**
 * Fox QPPI - Main orchestrator for the QR-DNA security system
 */

import type { FoxConfig, TailHandler, AlertPayload } from './Types.js';
import { ImmutableLedger } from '../security/immutableLedger.js';
import { Notifier } from '../alerts/notifier.js';

export class Fox {
  private config: FoxConfig;
  private tails: Map<string, TailHandler>;
  private ledger: ImmutableLedger;
  private notifier: Notifier | null;

  constructor(config: FoxConfig) {
    this.config = config;
    this.tails = config.tails;
    this.ledger = new ImmutableLedger();
    this.notifier = config.policies.notifier.webhookEnabled ? new Notifier() : null;
  }

  /**
   * Register a new tail handler
   */
  registerTail(name: string, handler: TailHandler): void {
    this.tails.set(name, handler);
  }

  /**
   * Process an event through all registered tails
   */
  async processEvent(eventData: Record<string, unknown>): Promise<void> {
    const alerts: AlertPayload[] = [];

    // Sort tails by priority (higher priority first)
    const sortedTails = Array.from(this.tails.entries()).sort((a, b) => {
      // Priority comparison would need tail metadata, for now use name
      return a[0].localeCompare(b[0]);
    });

    // Process through each tail
    for (const [name, handler] of sortedTails) {
      try {
        const alert = await handler(eventData);
        if (alert) {
          alerts.push(alert);
        }
      } catch (error) {
        console.error(`Error processing tail ${name}:`, error);
      }
    }

    // Record in immutable ledger
    this.ledger.append({
      action: 'event_processed',
      userId: eventData.userId as string || 'unknown',
      timestamp: Date.now(),
      metadata: {
        alertCount: alerts.length,
        tailsProcessed: sortedTails.length,
      },
    });

    // Send alerts via notifier
    if (this.notifier && alerts.length > 0) {
      for (const alert of alerts) {
        try {
          await this.notifier.send(alert);
        } catch (error) {
          console.error(`Error sending alert from ${alert.tailName}:`, error);
        }
      }
    }
  }

  /**
   * Get the current ledger state
   */
  getLedger(): ImmutableLedger {
    return this.ledger;
  }

  /**
   * Verify ledger integrity
   */
  verifyLedgerIntegrity(): boolean {
    return this.ledger.verify();
  }

  /**
   * Get registered tails
   */
  getTails(): string[] {
    return Array.from(this.tails.keys());
  }
}

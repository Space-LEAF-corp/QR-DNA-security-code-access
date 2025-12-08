/**
 * Immutable Ledger using SHA-256 for tamper-evident audit trails
 */

import { createHash } from 'crypto';
import type { LedgerEntry } from '../core/Types.js';

export class ImmutableLedger {
  private entries: LedgerEntry[];
  private lastHash?: string;

  constructor() {
    this.entries = [];
  }

  async append(data: { action: string; data: Record<string, unknown>; actor?: string }): Promise<LedgerEntry> {
    const entry: LedgerEntry = {
      id: this.generateId(),
      timestamp: Date.now(),
      action: data.action,
      actor: data.actor,
      data: data.data,
      previousHash: this.lastHash,
      hash: ''
    };

    // Calculate hash
    entry.hash = this.calculateHash(entry);
    this.lastHash = entry.hash;

    this.entries.push(entry);
    return entry;
  }

  private calculateHash(entry: Omit<LedgerEntry, 'hash'>): string {
    const data = JSON.stringify({
      id: entry.id,
      timestamp: entry.timestamp,
      action: entry.action,
      actor: entry.actor,
      data: entry.data,
      previousHash: entry.previousHash
    });

    return createHash('sha256').update(data).digest('hex');
  }

  private generateId(): string {
    return `${Date.now()}-${Math.random().toString(36).substring(2, 15)}`;
  }

  verify(): boolean {
    if (this.entries.length === 0) {
      return true;
    }

    let previousHash: string | undefined = undefined;

    for (const entry of this.entries) {
      // Verify previous hash matches
      if (entry.previousHash !== previousHash) {
        return false;
      }

      // Verify current hash
      const expectedHash = this.calculateHash({
        id: entry.id,
        timestamp: entry.timestamp,
        action: entry.action,
        actor: entry.actor,
        data: entry.data,
        previousHash: entry.previousHash
      });

      if (entry.hash !== expectedHash) {
        return false;
      }

      previousHash = entry.hash;
    }

    return true;
  }

  getEntries(): LedgerEntry[] {
    return [...this.entries];
  }

  getLastEntry(): LedgerEntry | undefined {
    return this.entries[this.entries.length - 1];
  }

  getEntriesByAction(action: string): LedgerEntry[] {
    return this.entries.filter(entry => entry.action === action);
  }

  getEntriesByActor(actor: string): LedgerEntry[] {
    return this.entries.filter(entry => entry.actor === actor);
  }

  size(): number {
    return this.entries.length;
  }
}

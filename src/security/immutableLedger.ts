/**
 * Immutable Ledger implementation using Node.js crypto SHA-256
 */

import { createHash } from 'crypto';
import type { LedgerEntry } from '../core/Types.js';

export class ImmutableLedger {
  private chain: LedgerEntry[];
  private genesisHash: string;

  constructor() {
    this.genesisHash = this.calculateHash('GENESIS_BLOCK', '', 0, {});
    this.chain = [];
  }

  /**
   * Calculate SHA-256 hash of ledger entry data
   */
  private calculateHash(
    action: string,
    previousHash: string,
    timestamp: number,
    metadata: Record<string, unknown>
  ): string {
    const data = JSON.stringify({ action, previousHash, timestamp, metadata });
    const hash = createHash('sha256').update(data).digest('hex');
    return `sha256:${hash}`;
  }

  /**
   * Append a new entry to the ledger
   */
  append(data: {
    action: string;
    userId: string;
    timestamp: number;
    metadata: Record<string, unknown>;
  }): string {
    const previousHash = this.chain.length > 0 
      ? this.chain[this.chain.length - 1].hash 
      : this.genesisHash;

    const hash = this.calculateHash(
      data.action,
      previousHash,
      data.timestamp,
      { ...data.metadata, userId: data.userId }
    );

    const entry: LedgerEntry = {
      hash,
      previousHash,
      timestamp: data.timestamp,
      action: data.action,
      userId: data.userId,
      metadata: data.metadata,
    };

    this.chain.push(entry);
    return hash;
  }

  /**
   * Verify the integrity of the entire ledger chain
   */
  verify(): boolean {
    if (this.chain.length === 0) {
      return true;
    }

    // Verify first entry links to genesis
    if (this.chain[0].previousHash !== this.genesisHash) {
      return false;
    }

    // Verify each subsequent entry
    for (let i = 0; i < this.chain.length; i++) {
      const entry = this.chain[i];
      
      // Recalculate hash
      const calculatedHash = this.calculateHash(
        entry.action,
        entry.previousHash,
        entry.timestamp,
        { ...entry.metadata, userId: entry.userId }
      );

      // Verify hash matches
      if (entry.hash !== calculatedHash) {
        return false;
      }

      // Verify chain links (except for first entry)
      if (i > 0 && entry.previousHash !== this.chain[i - 1].hash) {
        return false;
      }
    }

    return true;
  }

  /**
   * Get all ledger entries
   */
  getEntries(): readonly LedgerEntry[] {
    return Object.freeze([...this.chain]);
  }

  /**
   * Get entries for a specific user
   */
  getEntriesForUser(userId: string): readonly LedgerEntry[] {
    return Object.freeze(this.chain.filter(entry => entry.userId === userId));
  }

  /**
   * Get the latest entry
   */
  getLatestEntry(): LedgerEntry | null {
    return this.chain.length > 0 ? this.chain[this.chain.length - 1] : null;
  }

  /**
   * Get ledger size
   */
  size(): number {
    return this.chain.length;
  }
}

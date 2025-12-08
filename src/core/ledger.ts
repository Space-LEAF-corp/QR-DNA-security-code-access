/**
 * Immutable ledger implementation with SHA-256 hashing
 */

import { createHash } from 'node:crypto';
import { sign } from '../security/crypto.js';
import type { LedgerEntry, LedgerConfig, ValidationResult } from './types.js';

export class ImmutableLedger {
  private entries: LedgerEntry[] = [];
  private config: LedgerConfig;

  constructor(config: LedgerConfig = {}) {
    this.config = {
      maxSize: config.maxSize || 10000,
      requireSignature: config.requireSignature || false,
      signingKey: config.signingKey,
    };
  }

  /**
   * Compute SHA-256 hash with deterministic prefix
   */
  private computeHash(data: string): string {
    const hash = createHash('sha256').update(data).digest('hex');
    return `sha256:${hash}`;
  }

  /**
   * Append a new entry to the ledger (append-only)
   */
  async append(data: unknown): Promise<LedgerEntry> {
    if (this.entries.length >= (this.config.maxSize || 10000)) {
      throw new Error('Ledger has reached maximum size');
    }

    const previousHash = this.entries.length > 0 
      ? this.entries[this.entries.length - 1].hash 
      : 'sha256:genesis';

    const id = `entry-${Date.now()}-${this.entries.length}`;
    const timestamp = Date.now();
    
    // Create hash from entry data
    const dataString = JSON.stringify({ id, timestamp, data, previousHash });
    const hash = this.computeHash(dataString);

    // Create entry
    const entry: LedgerEntry = {
      id,
      timestamp,
      data,
      hash,
      previousHash,
    };

    // Add optional signature
    if (this.config.requireSignature && this.config.signingKey) {
      const signature = await sign(hash, this.config.signingKey);
      entry.signature = signature;
    }

    // Append-only: no modifications to existing entries
    this.entries.push(entry);

    return entry;
  }

  /**
   * Get all entries (read-only)
   */
  getEntries(): ReadonlyArray<Readonly<LedgerEntry>> {
    return this.entries;
  }

  /**
   * Get a specific entry by ID (read-only)
   */
  getEntry(id: string): Readonly<LedgerEntry> | undefined {
    return this.entries.find(entry => entry.id === id);
  }

  /**
   * Validate ledger integrity
   */
  validate(): ValidationResult {
    const errors: string[] = [];

    for (let i = 0; i < this.entries.length; i++) {
      const entry = this.entries[i];
      const expectedPreviousHash = i === 0 
        ? 'sha256:genesis' 
        : this.entries[i - 1].hash;

      if (entry.previousHash !== expectedPreviousHash) {
        errors.push(`Entry ${entry.id}: Invalid previous hash`);
      }

      // Recompute hash to verify integrity
      const dataString = JSON.stringify({
        id: entry.id,
        timestamp: entry.timestamp,
        data: entry.data,
        previousHash: entry.previousHash,
      });
      const expectedHash = this.computeHash(dataString);

      if (entry.hash !== expectedHash) {
        errors.push(`Entry ${entry.id}: Hash mismatch`);
      }
    }

    return {
      valid: errors.length === 0,
      errors: errors.length > 0 ? errors : undefined,
    };
  }

  /**
   * Get ledger size
   */
  size(): number {
    return this.entries.length;
  }

  /**
   * Export ledger as JSON
   */
  export(): string {
    return JSON.stringify(this.entries, null, 2);
  }

  /**
   * Import ledger from JSON (for recovery only)
   */
  import(json: string): void {
    const imported = JSON.parse(json) as LedgerEntry[];
    
    // Validate imported data
    if (!Array.isArray(imported)) {
      throw new Error('Invalid ledger data: expected array');
    }

    this.entries = imported;

    // Validate integrity after import
    const validation = this.validate();
    if (!validation.valid) {
      throw new Error(`Ledger validation failed: ${validation.errors?.join(', ')}`);
    }
  }
}

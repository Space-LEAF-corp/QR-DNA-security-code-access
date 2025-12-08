/**
 * ImmutableLedger: Cryptographic ledger using SHA-256 with optional tweetnacl signing
 */

import { createHash } from 'crypto';
import nacl from 'tweetnacl';
import type { LedgerEntry } from '../core/Types.js';

export class ImmutableLedger {
  private entries: LedgerEntry[] = [];
  private lastHash: string = 'sha256:genesis';
  private secretKey?: Uint8Array;

  constructor(secretKey?: Uint8Array) {
    this.secretKey = secretKey;
  }

  /**
   * Add a new entry to the ledger
   */
  async addEntry(action: string, actor: string, data: Record<string, any>): Promise<LedgerEntry> {
    const timestamp = Date.now();
    const entryData = {
      timestamp,
      action,
      actor,
      data,
      previousHash: this.lastHash,
    };

    // Create SHA-256 hash
    const hash = this.computeHash(entryData);

    // Optional: Sign with tweetnacl if secretKey provided
    let signature: string | undefined;
    if (this.secretKey) {
      const message = Buffer.from(hash, 'utf-8');
      const signatureBytes = nacl.sign.detached(message, this.secretKey);
      signature = Buffer.from(signatureBytes).toString('base64');
    }

    const entry: LedgerEntry = {
      timestamp,
      action,
      actor,
      data,
      hash,
      signature,
    };

    this.entries.push(entry);
    this.lastHash = hash;

    return entry;
  }

  /**
   * Compute SHA-256 hash with 'sha256:' prefix
   */
  private computeHash(data: any): string {
    const hash = createHash('sha256');
    hash.update(JSON.stringify(data));
    return 'sha256:' + hash.digest('hex');
  }

  /**
   * Get the current head hash
   */
  getHeadHash(): string {
    return this.lastHash;
  }

  /**
   * Get all ledger entries
   */
  getEntries(): LedgerEntry[] {
    return [...this.entries];
  }

  /**
   * Verify ledger integrity
   */
  verifyIntegrity(): boolean {
    let expectedHash = 'sha256:genesis';

    for (const entry of this.entries) {
      const entryData = {
        timestamp: entry.timestamp,
        action: entry.action,
        actor: entry.actor,
        data: entry.data,
        previousHash: expectedHash,
      };

      const computedHash = this.computeHash(entryData);
      if (computedHash !== entry.hash) {
        return false;
      }

      expectedHash = entry.hash;
    }

    return expectedHash === this.lastHash;
  }
}

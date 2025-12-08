import { createHash } from 'crypto';

/**
 * Represents a single entry in the immutable ledger
 */
export interface LedgerEntry {
  id: string;
  timestamp: number;
  data: string;
  hash: string;
  previousHash: string;
  signature?: string;
}

/**
 * Options for creating a new ledger entry
 */
export interface LedgerEntryOptions {
  data: string;
  signFn?: (data: string) => string;
}

/**
 * Immutable Ledger implementation with SHA-256 hashing
 * 
 * Features:
 * - Append-only data structure
 * - SHA-256 hash chaining for integrity
 * - Optional digital signatures with tweetnacl
 * - Deterministic hash prefixes (sha256:)
 */
export class ImmutableLedger {
  private entries: LedgerEntry[] = [];
  private readonly genesisHash = 'sha256:0000000000000000000000000000000000000000000000000000000000000000';

  /**
   * Creates a new ImmutableLedger instance
   */
  constructor() {
    // Initialize with empty ledger
  }

  /**
   * Computes SHA-256 hash with deterministic prefix
   * @param data - The data to hash
   * @returns SHA-256 hash with "sha256:" prefix
   */
  private computeHash(data: string): string {
    const hash = createHash('sha256')
      .update(data)
      .digest('hex');
    return `sha256:${hash}`;
  }

  /**
   * Appends a new entry to the ledger
   * @param options - Entry options including data and optional signing function
   * @returns The newly created ledger entry
   */
  public append(options: LedgerEntryOptions): LedgerEntry {
    const { data, signFn } = options;
    const timestamp = Date.now();
    const entryIndex = this.entries.length;
    const previousHash = entryIndex > 0
      ? this.entries[entryIndex - 1].hash
      : this.genesisHash;

    // Generate unique ID
    const id = `entry_${timestamp}_${entryIndex}`;

    // Compute hash of entry data
    const entryData = JSON.stringify({
      id,
      timestamp,
      data,
      previousHash
    });
    const hash = this.computeHash(entryData);

    // Create entry
    const entry: LedgerEntry = {
      id,
      timestamp,
      data,
      hash,
      previousHash
    };

    // Optionally sign the entry
    if (signFn) {
      entry.signature = signFn(entryData);
    }

    // Append to ledger (immutable operation)
    this.entries.push(entry);

    return entry;
  }

  /**
   * Retrieves an entry by its ID
   * @param id - The entry ID
   * @returns The ledger entry or undefined if not found
   */
  public getEntry(id: string): LedgerEntry | undefined {
    return this.entries.find(entry => entry.id === id);
  }

  /**
   * Gets all entries in the ledger
   * @returns Array of all ledger entries (read-only copy)
   */
  public getAllEntries(): ReadonlyArray<LedgerEntry> {
    return [...this.entries];
  }

  /**
   * Gets the number of entries in the ledger
   * @returns The entry count
   */
  public size(): number {
    return this.entries.length;
  }

  /**
   * Verifies the integrity of the entire ledger
   * @returns True if ledger is valid, false otherwise
   */
  public verify(): boolean {
    for (let i = 0; i < this.entries.length; i++) {
      const entry = this.entries[i];
      const expectedPreviousHash = i > 0
        ? this.entries[i - 1].hash
        : this.genesisHash;

      // Check if previous hash matches
      if (entry.previousHash !== expectedPreviousHash) {
        return false;
      }

      // Recompute hash and verify
      const entryData = JSON.stringify({
        id: entry.id,
        timestamp: entry.timestamp,
        data: entry.data,
        previousHash: entry.previousHash
      });
      const computedHash = this.computeHash(entryData);

      if (entry.hash !== computedHash) {
        return false;
      }
    }

    return true;
  }

  /**
   * Exports the ledger as a JSON string
   * @returns JSON representation of the ledger
   */
  public export(): string {
    return JSON.stringify(this.entries, null, 2);
  }
}

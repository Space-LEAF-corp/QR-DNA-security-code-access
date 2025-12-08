/**
 * Tail system for tracking and monitoring data streams
 */

/**
 * Tail entry interface
 */
export interface TailEntry {
  id: string;
  timestamp: number;
  type: string;
  data: unknown;
}

/**
 * Tail options
 */
export interface TailOptions {
  maxSize?: number;
  retentionMs?: number;
}

/**
 * Tail manager for tracking data streams and events
 */
export class TailManager {
  private entries: TailEntry[] = [];
  private readonly maxSize: number;
  private readonly retentionMs: number;

  /**
   * Creates a new TailManager
   * @param options - Configuration options
   */
  constructor(options: TailOptions = {}) {
    this.maxSize = options.maxSize ?? 1000;
    this.retentionMs = options.retentionMs ?? 7 * 24 * 60 * 60 * 1000; // 7 days default
  }

  /**
   * Appends a new entry to the tail
   * @param type - Entry type/category
   * @param data - Entry data
   * @returns The created entry
   */
  public append(type: string, data: unknown): TailEntry {
    const timestamp = Date.now();
    const entryIndex = this.entries.length;
    const entry: TailEntry = {
      id: `tail_${timestamp}_${entryIndex}`,
      timestamp,
      type,
      data
    };

    this.entries.push(entry);
    this.cleanup();

    return entry;
  }

  /**
   * Gets entries by type
   * @param type - The type to filter by
   * @returns Array of filtered entries
   */
  public getEntriesByType(type: string): ReadonlyArray<TailEntry> {
    return this.entries.filter(entry => entry.type === type);
  }

  /**
   * Gets all entries
   * @returns Array of all entries
   */
  public getAllEntries(): ReadonlyArray<TailEntry> {
    return [...this.entries];
  }

  /**
   * Gets entries within a time range
   * @param startTime - Start timestamp
   * @param endTime - End timestamp
   * @returns Array of entries in the time range
   */
  public getEntriesInRange(startTime: number, endTime: number): ReadonlyArray<TailEntry> {
    return this.entries.filter(
      entry => entry.timestamp >= startTime && entry.timestamp <= endTime
    );
  }

  /**
   * Gets the most recent N entries
   * @param count - Number of entries to retrieve
   * @returns Array of most recent entries
   */
  public getRecentEntries(count: number): ReadonlyArray<TailEntry> {
    return this.entries.slice(-count);
  }

  /**
   * Clears all entries
   */
  public clear(): void {
    this.entries = [];
  }

  /**
   * Gets the current size
   * @returns Number of entries
   */
  public size(): number {
    return this.entries.length;
  }

  /**
   * Cleans up old entries based on retention policy
   */
  private cleanup(): void {
    const now = Date.now();
    const cutoffTime = now - this.retentionMs;

    // Remove old entries
    this.entries = this.entries.filter(entry => entry.timestamp > cutoffTime);

    // Enforce max size
    if (this.entries.length > this.maxSize) {
      this.entries = this.entries.slice(-this.maxSize);
    }
  }
}

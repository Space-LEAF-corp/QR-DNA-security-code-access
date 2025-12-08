/**
 * Audit trail (tails) management system
 */

import type { TailEntry, TailConfig, TailQuery } from './types.js';

export class TailManager {
  private entries: TailEntry[] = [];
  private config: TailConfig;

  constructor(config: TailConfig = {}) {
    this.config = {
      retentionDays: config.retentionDays || 90,
      maxSize: config.maxSize || 1000000,
      compressionEnabled: config.compressionEnabled || true,
    };
  }

  /**
   * Record a new audit trail entry
   */
  record(
    action: string,
    actor: string,
    resource: string,
    result: 'success' | 'failure',
    metadata?: Record<string, unknown>
  ): TailEntry {
    // Clean up old entries before adding new one
    this.cleanup();

    if (this.entries.length >= (this.config.maxSize || 1000000)) {
      throw new Error('Tail storage has reached maximum size');
    }

    const entry: TailEntry = {
      id: `tail-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      timestamp: Date.now(),
      action,
      actor,
      resource,
      result,
      metadata,
    };

    this.entries.push(entry);
    return entry;
  }

  /**
   * Query audit trail entries
   */
  query(filter?: TailQuery): TailEntry[] {
    if (!filter) {
      return [...this.entries];
    }

    return this.entries.filter(entry => {
      if (filter.startTime && entry.timestamp < filter.startTime) {
        return false;
      }
      if (filter.endTime && entry.timestamp > filter.endTime) {
        return false;
      }
      if (filter.actor && entry.actor !== filter.actor) {
        return false;
      }
      if (filter.action && entry.action !== filter.action) {
        return false;
      }
      if (filter.resource && entry.resource !== filter.resource) {
        return false;
      }
      if (filter.result && entry.result !== filter.result) {
        return false;
      }
      return true;
    });
  }

  /**
   * Get a specific entry by ID
   */
  getEntry(id: string): TailEntry | undefined {
    return this.entries.find(entry => entry.id === id);
  }

  /**
   * Clean up old entries based on retention policy
   */
  private cleanup(): void {
    const retentionMs = (this.config.retentionDays || 90) * 24 * 60 * 60 * 1000;
    const cutoffTime = Date.now() - retentionMs;
    
    this.entries = this.entries.filter(entry => entry.timestamp >= cutoffTime);
  }

  /**
   * Get statistics
   */
  getStats(): {
    totalEntries: number;
    successCount: number;
    failureCount: number;
    oldestEntry: number | null;
    newestEntry: number | null;
  } {
    const successCount = this.entries.filter(e => e.result === 'success').length;
    const failureCount = this.entries.filter(e => e.result === 'failure').length;
    
    const timestamps = this.entries.map(e => e.timestamp);
    const oldestEntry = timestamps.length > 0 ? Math.min(...timestamps) : null;
    const newestEntry = timestamps.length > 0 ? Math.max(...timestamps) : null;

    return {
      totalEntries: this.entries.length,
      successCount,
      failureCount,
      oldestEntry,
      newestEntry,
    };
  }

  /**
   * Export entries as JSON
   */
  export(): string {
    return JSON.stringify(this.entries, null, 2);
  }

  /**
   * Clear all entries (use with caution)
   */
  clear(): void {
    this.entries = [];
  }
}

/**
 * Communal Broadcast tail - Community-wide announcements and notifications
 */

import { Tail } from '../core/Tail.js';
import type { TailConfig } from '../core/Types.js';

export class CommunalBroadcastTail extends Tail {
  private broadcasts: Array<{ id: string; message: string; timestamp: number }>;
  private subscribers: Set<string>;

  constructor(config: TailConfig) {
    super(config);
    this.broadcasts = [];
    this.subscribers = new Set();
  }

  async initialize(): Promise<void> {
    console.log('📢 Communal Broadcast tail: Initializing broadcast system');
  }

  broadcast(message: string): string {
    const id = `broadcast-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
    this.broadcasts.push({ id, message, timestamp: Date.now() });
    
    // Keep only last 100 broadcasts
    if (this.broadcasts.length > 100) {
      this.broadcasts = this.broadcasts.slice(-100);
    }

    return id;
  }

  subscribe(userId: string): void {
    this.subscribers.add(userId);
  }

  unsubscribe(userId: string): void {
    this.subscribers.delete(userId);
  }

  getRecentBroadcasts(limit: number = 10): typeof this.broadcasts {
    return this.broadcasts.slice(-limit);
  }
}

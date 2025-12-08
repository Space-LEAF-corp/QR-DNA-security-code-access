/**
 * Tail - Child process lifecycle management
 */

import type { TailConfig } from './Types.js';

export class Tail {
  private config: TailConfig;
  private running: boolean;
  private startTime?: number;

  constructor(config: TailConfig) {
    this.config = config;
    this.running = false;
  }

  async start(): Promise<void> {
    if (this.running) {
      throw new Error(`Tail "${this.config.name}" is already running`);
    }

    this.running = true;
    this.startTime = Date.now();
    
    // Initialize tail-specific logic
    await this.initialize();
  }

  async stop(): Promise<void> {
    if (!this.running) {
      return;
    }

    this.running = false;
    await this.cleanup();
  }

  protected async initialize(): Promise<void> {
    // Tail-specific initialization logic
    // This is overridden by specific tail implementations
  }

  protected async cleanup(): Promise<void> {
    // Tail-specific cleanup logic
  }

  isRunning(): boolean {
    return this.running;
  }

  getName(): string {
    return this.config.name;
  }

  getUptime(): number {
    if (!this.startTime) {
      return 0;
    }
    return Date.now() - this.startTime;
  }

  getConfig(): TailConfig {
    return { ...this.config };
  }
}

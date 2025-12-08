/**
 * Fox: Main orchestration system
 */

import { TailRegistry } from './Tail.js';
import type { FoxConfig } from './Types.js';

export class Fox {
  private readonly config: FoxConfig;
  private readonly tailRegistry: TailRegistry;

  constructor(config: FoxConfig = {}) {
    this.config = config;
    this.tailRegistry = new TailRegistry();
  }

  getTailRegistry(): TailRegistry {
    return this.tailRegistry;
  }

  getConfig(): FoxConfig {
    return { ...this.config };
  }

  async processAction(context: any): Promise<void> {
    // Execute all registered tail behaviors
    await this.tailRegistry.executeAll(context);
  }
}

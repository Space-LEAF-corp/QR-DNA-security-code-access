/**
 * Tail: Represents a behavior module in the Fox system
 */

import type { TailBehavior } from './Types.js';

export class Tail implements TailBehavior {
  public readonly name: string;
  private readonly handler: (context: any) => Promise<void>;

  constructor(name: string, handler: (context: any) => Promise<void>) {
    this.name = name;
    this.handler = handler;
  }

  async execute(context: any): Promise<void> {
    await this.handler(context);
  }
}

export class TailRegistry {
  private tails: Map<string, Tail> = new Map();

  register(tail: Tail): void {
    this.tails.set(tail.name, tail);
  }

  get(name: string): Tail | undefined {
    return this.tails.get(name);
  }

  getAll(): Tail[] {
    return Array.from(this.tails.values());
  }

  async executeAll(context: any): Promise<void> {
    for (const tail of this.tails.values()) {
      await tail.execute(context);
    }
  }
}

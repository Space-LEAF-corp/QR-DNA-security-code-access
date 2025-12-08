/**
 * Parents tail - Parental controls and monitoring
 */

import { Tail } from '../core/Tail.js';
import type { TailConfig } from '../core/Types.js';

export class ParentsTail extends Tail {
  private parentalLinks: Map<string, string[]>; // parent -> children

  constructor(config: TailConfig) {
    super(config);
    this.parentalLinks = new Map();
  }

  async initialize(): Promise<void> {
    console.log('👨‍👩‍👧‍👦 Parents tail: Initializing parental controls');
  }

  linkChild(parentId: string, childId: string): void {
    const children = this.parentalLinks.get(parentId) || [];
    if (!children.includes(childId)) {
      children.push(childId);
      this.parentalLinks.set(parentId, children);
    }
  }

  getChildren(parentId: string): string[] {
    return this.parentalLinks.get(parentId) || [];
  }
}

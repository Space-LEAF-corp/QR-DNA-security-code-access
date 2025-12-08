/**
 * Security deterrence mechanisms
 */

export class Deterrence {
  private failedAttempts: Map<string, number>;
  private blockedIps: Set<string>;
  private readonly maxAttempts: number;
  private readonly blockDuration: number;

  constructor(config: { maxAttempts?: number; blockDuration?: number } = {}) {
    this.failedAttempts = new Map();
    this.blockedIps = new Set();
    this.maxAttempts = config.maxAttempts || 5;
    this.blockDuration = config.blockDuration || 15 * 60 * 1000; // 15 minutes
  }

  recordFailedAttempt(identifier: string): void {
    const attempts = (this.failedAttempts.get(identifier) || 0) + 1;
    this.failedAttempts.set(identifier, attempts);

    if (attempts >= this.maxAttempts) {
      this.blockIdentifier(identifier);
    }
  }

  recordSuccessfulAttempt(identifier: string): void {
    this.failedAttempts.delete(identifier);
  }

  isBlocked(identifier: string): boolean {
    return this.blockedIps.has(identifier);
  }

  private blockIdentifier(identifier: string): void {
    this.blockedIps.add(identifier);
    
    // Automatically unblock after duration
    setTimeout(() => {
      this.unblockIdentifier(identifier);
    }, this.blockDuration);
  }

  unblockIdentifier(identifier: string): void {
    this.blockedIps.delete(identifier);
    this.failedAttempts.delete(identifier);
  }

  getFailedAttempts(identifier: string): number {
    return this.failedAttempts.get(identifier) || 0;
  }

  getBlockedIdentifiers(): string[] {
    return Array.from(this.blockedIps);
  }

  reset(): void {
    this.failedAttempts.clear();
    this.blockedIps.clear();
  }
}

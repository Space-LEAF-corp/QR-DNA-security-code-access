/**
 * Base class for Fox QPPI tail components
 */

import type { TailConfig, AlertPayload } from './Types.js';

export abstract class Tail {
  protected config: TailConfig;
  protected name: string;

  constructor(name: string, config: TailConfig) {
    this.name = name;
    this.config = config;
  }

  /**
   * Check if this tail is enabled
   */
  isEnabled(): boolean {
    return this.config.enabled;
  }

  /**
   * Get the priority of this tail
   */
  getPriority(): number {
    return this.config.priority;
  }

  /**
   * Get the alert threshold for this tail
   */
  getAlertThreshold(): 'low' | 'medium' | 'high' {
    return this.config.alertThreshold;
  }

  /**
   * Process data and potentially generate an alert
   * Must be implemented by subclasses
   */
  abstract process(data: Record<string, unknown>): Promise<AlertPayload | null>;

  /**
   * Validate that data meets minimum requirements
   */
  protected validateData(data: Record<string, unknown>, requiredFields: string[]): boolean {
    for (const field of requiredFields) {
      if (!(field in data)) {
        return false;
      }
    }
    return true;
  }

  /**
   * Create an alert payload
   */
  protected createAlert(
    severity: 'low' | 'medium' | 'high' | 'critical',
    message: string,
    metadata: Record<string, unknown> = {}
  ): AlertPayload {
    return {
      tailName: this.name,
      severity,
      message,
      timestamp: Date.now(),
      metadata,
    };
  }
}

/**
 * Deterrence System - Escalate responses to security violations
 */

export type DeterrenceLevel = 'warning' | 'alert' | 'lockout' | 'report';

export interface DeterrenceRecord {
  userId: string;
  violations: number;
  level: DeterrenceLevel;
  lastViolation: number;
  lockedUntil?: number;
}

export class DeterrenceSystem {
  private records: Map<string, DeterrenceRecord>;
  private config: {
    maxViolations: number;
    lockoutDurationMinutes: number;
    reportToAuthorities: boolean;
  };

  constructor(config?: {
    maxViolations?: number;
    lockoutDurationMinutes?: number;
    reportToAuthorities?: boolean;
  }) {
    this.records = new Map();
    this.config = {
      maxViolations: config?.maxViolations || 3,
      lockoutDurationMinutes: config?.lockoutDurationMinutes || 30,
      reportToAuthorities: config?.reportToAuthorities || false,
    };
  }

  /**
   * Record a security violation
   */
  recordViolation(userId: string, metadata?: Record<string, unknown>): DeterrenceLevel {
    const existing = this.records.get(userId);
    const now = Date.now();

    let violations = 1;
    let level: DeterrenceLevel = 'warning';

    if (existing) {
      violations = existing.violations + 1;
      
      // Reset violations if last violation was more than 24 hours ago
      if (now - existing.lastViolation > 24 * 60 * 60 * 1000) {
        violations = 1;
      }
    }

    // Determine deterrence level
    if (violations === 1) {
      level = 'warning';
    } else if (violations === 2) {
      level = 'alert';
    } else if (violations >= this.config.maxViolations) {
      level = 'lockout';
      
      if (violations > this.config.maxViolations * 2) {
        level = 'report';
      }
    }

    const record: DeterrenceRecord = {
      userId,
      violations,
      level,
      lastViolation: now,
    };

    // Apply lockout if necessary
    if (level === 'lockout' || level === 'report') {
      record.lockedUntil = now + this.config.lockoutDurationMinutes * 60 * 1000;
    }

    this.records.set(userId, record);

    // Log for authority reporting
    if (level === 'report' && this.config.reportToAuthorities) {
      this.reportToAuthorities(userId, record, metadata);
    }

    return level;
  }

  /**
   * Check if user is currently locked out
   */
  isLockedOut(userId: string): boolean {
    const record = this.records.get(userId);
    
    if (!record || !record.lockedUntil) {
      return false;
    }

    const now = Date.now();
    
    if (now < record.lockedUntil) {
      return true;
    }

    // Lockout expired, clear it
    record.lockedUntil = undefined;
    if (record.level === 'lockout') {
      record.level = 'alert';
    }
    
    return false;
  }

  /**
   * Get deterrence record for a user
   */
  getRecord(userId: string): DeterrenceRecord | null {
    return this.records.get(userId) || null;
  }

  /**
   * Clear violations for a user (e.g., after successful re-authentication)
   */
  clearViolations(userId: string): boolean {
    return this.records.delete(userId);
  }

  /**
   * Get remaining lockout time in milliseconds
   */
  getRemainingLockoutTime(userId: string): number {
    const record = this.records.get(userId);
    
    if (!record || !record.lockedUntil) {
      return 0;
    }

    const remaining = record.lockedUntil - Date.now();
    return remaining > 0 ? remaining : 0;
  }

  /**
   * Report to authorities (placeholder for actual implementation)
   */
  private reportToAuthorities(
    userId: string,
    record: DeterrenceRecord,
    metadata?: Record<string, unknown>
  ): void {
    console.warn('[DETERRENCE] Reporting to authorities:', {
      userId,
      violations: record.violations,
      level: record.level,
      metadata,
    });
    
    // In production, this would:
    // - Send to security monitoring system
    // - Create incident report
    // - Notify security team
    // - Potentially contact law enforcement for severe violations
  }

  /**
   * Get escalation level name
   */
  getLevelName(level: DeterrenceLevel): string {
    const names: Record<DeterrenceLevel, string> = {
      warning: 'Warning - First Offense',
      alert: 'Alert - Repeated Offense',
      lockout: 'Lockout - Access Denied',
      report: 'Report - Authorities Notified',
    };
    
    return names[level];
  }

  /**
   * Get statistics
   */
  getStatistics(): {
    totalUsers: number;
    warned: number;
    alerted: number;
    lockedOut: number;
    reported: number;
  } {
    const stats = {
      totalUsers: this.records.size,
      warned: 0,
      alerted: 0,
      lockedOut: 0,
      reported: 0,
    };

    for (const record of this.records.values()) {
      switch (record.level) {
        case 'warning':
          stats.warned++;
          break;
        case 'alert':
          stats.alerted++;
          break;
        case 'lockout':
          stats.lockedOut++;
          break;
        case 'report':
          stats.reported++;
          break;
      }
    }

    return stats;
  }
}

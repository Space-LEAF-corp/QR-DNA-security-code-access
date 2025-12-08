/**
 * Alert system for monitoring and notifications
 */

/**
 * Severity levels for alerts
 */
export enum AlertSeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

/**
 * Alert interface
 */
export interface Alert {
  id: string;
  timestamp: number;
  severity: AlertSeverity;
  message: string;
  source: string;
  metadata?: Record<string, unknown>;
}

/**
 * Alert manager for handling system alerts
 */
export class AlertManager {
  private alerts: Alert[] = [];
  private listeners: Array<(alert: Alert) => void> = [];

  /**
   * Creates a new alert
   * @param severity - Alert severity level
   * @param message - Alert message
   * @param source - Source of the alert
   * @param metadata - Optional metadata
   * @returns The created alert
   */
  public createAlert(
    severity: AlertSeverity,
    message: string,
    source: string,
    metadata?: Record<string, unknown>
  ): Alert {
    const timestamp = Date.now();
    const alertIndex = this.alerts.length;
    const alert: Alert = {
      id: `alert_${timestamp}_${alertIndex}`,
      timestamp,
      severity,
      message,
      source,
      metadata
    };

    this.alerts.push(alert);
    this.notifyListeners(alert);

    return alert;
  }

  /**
   * Registers a listener for new alerts
   * @param listener - Callback function to handle alerts
   */
  public onAlert(listener: (alert: Alert) => void): void {
    this.listeners.push(listener);
  }

  /**
   * Gets all alerts
   * @returns Array of all alerts
   */
  public getAllAlerts(): ReadonlyArray<Alert> {
    return [...this.alerts];
  }

  /**
   * Gets alerts filtered by severity
   * @param severity - The severity to filter by
   * @returns Array of filtered alerts
   */
  public getAlertsBySeverity(severity: AlertSeverity): ReadonlyArray<Alert> {
    return this.alerts.filter(alert => alert.severity === severity);
  }

  /**
   * Clears all alerts
   */
  public clearAlerts(): void {
    this.alerts = [];
  }

  /**
   * Notifies all registered listeners of a new alert
   * @param alert - The alert to notify about
   */
  private notifyListeners(alert: Alert): void {
    for (const listener of this.listeners) {
      try {
        listener(alert);
      } catch (error) {
        console.error('Error in alert listener:', error);
      }
    }
  }
}

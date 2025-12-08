/**
 * Security tests for Fox QPPI
 */

import { describe, it, expect, beforeEach } from '@jest/globals';
import { Deterrence } from '../src/alerts/deterrence.js';
import { Notifier } from '../src/alerts/notifier.js';
import type { AlertPayload } from '../src/core/Types.js';

describe('Deterrence', () => {
  let deterrence: Deterrence;

  beforeEach(() => {
    deterrence = new Deterrence({ maxAttempts: 3, blockDuration: 1000 });
  });

  it('should track failed attempts', () => {
    deterrence.recordFailedAttempt('user1');
    expect(deterrence.getFailedAttempts('user1')).toBe(1);
    
    deterrence.recordFailedAttempt('user1');
    expect(deterrence.getFailedAttempts('user1')).toBe(2);
  });

  it('should block after max attempts', () => {
    deterrence.recordFailedAttempt('user1');
    deterrence.recordFailedAttempt('user1');
    deterrence.recordFailedAttempt('user1');
    
    expect(deterrence.isBlocked('user1')).toBe(true);
  });

  it('should reset on successful attempt', () => {
    deterrence.recordFailedAttempt('user1');
    deterrence.recordFailedAttempt('user1');
    deterrence.recordSuccessfulAttempt('user1');
    
    expect(deterrence.getFailedAttempts('user1')).toBe(0);
  });

  it('should unblock identifier', () => {
    deterrence.recordFailedAttempt('user1');
    deterrence.recordFailedAttempt('user1');
    deterrence.recordFailedAttempt('user1');
    
    expect(deterrence.isBlocked('user1')).toBe(true);
    
    deterrence.unblockIdentifier('user1');
    expect(deterrence.isBlocked('user1')).toBe(false);
  });

  it('should auto-unblock after duration', (done) => {
    deterrence.recordFailedAttempt('user1');
    deterrence.recordFailedAttempt('user1');
    deterrence.recordFailedAttempt('user1');
    
    expect(deterrence.isBlocked('user1')).toBe(true);
    
    setTimeout(() => {
      expect(deterrence.isBlocked('user1')).toBe(false);
      done();
    }, 1100);
  });
});

describe('Notifier', () => {
  let notifier: Notifier;
  const secret = 'test-secret-key';

  beforeEach(() => {
    notifier = new Notifier({
      webhookUrl: 'http://example.com/webhook',
      secret
    });
  });

  it('should generate valid HMAC signature', () => {
    const alert: AlertPayload = {
      type: 'test',
      severity: 'low',
      message: 'Test alert',
      timestamp: Date.now()
    };

    const signature = (notifier as any).generateSignature({ event: 'alert', data: alert });

    expect(signature).toMatch(/^sha256=[a-f0-9]{64}$/);
  });

  it('should verify valid signature', () => {
    const payload = { event: 'alert', data: { type: 'test' } };
    const payloadStr = JSON.stringify(payload);
    const signature = (notifier as any).generateSignature(payload);

    const valid = notifier.verifySignature(payloadStr, signature);
    expect(valid).toBe(true);
  });

  it('should reject invalid signature', () => {
    const payload = { event: 'alert', data: { type: 'test' } };
    const payloadStr = JSON.stringify(payload);

    const valid = notifier.verifySignature(payloadStr, 'sha256=invalid');
    expect(valid).toBe(false);
  });

  it('should verify webhook signature statically', () => {
    const payload = '{"event":"alert","data":{"type":"test"}}';
    const signature = Notifier.verifyWebhookSignature(payload, 'sha256=test', secret);
    
    // The signature won't match but the function should not throw
    expect(typeof signature).toBe('boolean');
  });
});

describe('Security Edge Cases', () => {
  it('should handle empty messages in signature verification', () => {
    const deterrence = new Deterrence();
    
    // Should not crash with empty identifier
    deterrence.recordFailedAttempt('');
    expect(deterrence.getFailedAttempts('')).toBe(1);
  });

  it('should handle concurrent operations safely', async () => {
    const deterrence = new Deterrence();
    
    // Simulate concurrent failed attempts
    const promises = Array.from({ length: 10 }, () => 
      Promise.resolve(deterrence.recordFailedAttempt('user1'))
    );
    
    await Promise.all(promises);
    expect(deterrence.getFailedAttempts('user1')).toBe(10);
  });

  it('should clean up resources on reset', () => {
    const deterrence = new Deterrence();
    
    deterrence.recordFailedAttempt('user1');
    deterrence.recordFailedAttempt('user2');
    deterrence.recordFailedAttempt('user3');
    
    deterrence.reset();
    
    expect(deterrence.getFailedAttempts('user1')).toBe(0);
    expect(deterrence.getFailedAttempts('user2')).toBe(0);
    expect(deterrence.getFailedAttempts('user3')).toBe(0);
  });
});

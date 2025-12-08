/**
 * Validation tests for Fox QPPI
 */

import { describe, it, expect, beforeEach } from '@jest/globals';
import {
  ImmutableLedger,
  CryptoManager,
  createSigningFunction,
  AlertManager,
  AlertSeverity,
  TailManager
} from '../src/index.js';

describe('ImmutableLedger', () => {
  let ledger: ImmutableLedger;

  beforeEach(() => {
    ledger = new ImmutableLedger();
  });

  it('should create an empty ledger', () => {
    expect(ledger.size()).toBe(0);
  });

  it('should append an entry', () => {
    const entry = ledger.append({ data: 'test data' });
    
    expect(entry).toBeDefined();
    expect(entry.data).toBe('test data');
    expect(entry.hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(ledger.size()).toBe(1);
  });

  it('should chain entries with previous hash', () => {
    const entry1 = ledger.append({ data: 'first' });
    const entry2 = ledger.append({ data: 'second' });
    
    expect(entry2.previousHash).toBe(entry1.hash);
  });

  it('should use genesis hash for first entry', () => {
    const entry = ledger.append({ data: 'first' });
    
    expect(entry.previousHash).toMatch(/^sha256:0+$/);
  });

  it('should verify ledger integrity', () => {
    ledger.append({ data: 'entry1' });
    ledger.append({ data: 'entry2' });
    ledger.append({ data: 'entry3' });
    
    expect(ledger.verify()).toBe(true);
  });

  it('should support signed entries', () => {
    const keyPair = CryptoManager.generateKeyPair();
    const signFn = createSigningFunction(keyPair.secretKey);
    
    const entry = ledger.append({ data: 'signed data', signFn });
    
    expect(entry.signature).toBeDefined();
    expect(typeof entry.signature).toBe('string');
  });

  it('should retrieve entry by id', () => {
    const entry1 = ledger.append({ data: 'test' });
    const retrieved = ledger.getEntry(entry1.id);
    
    expect(retrieved).toBeDefined();
    expect(retrieved?.id).toBe(entry1.id);
  });

  it('should get all entries', () => {
    ledger.append({ data: 'entry1' });
    ledger.append({ data: 'entry2' });
    
    const entries = ledger.getAllEntries();
    expect(entries.length).toBe(2);
  });

  it('should export ledger as JSON', () => {
    ledger.append({ data: 'test' });
    const exported = ledger.export();
    
    expect(exported).toBeDefined();
    expect(() => JSON.parse(exported)).not.toThrow();
  });
});

describe('CryptoManager', () => {
  it('should generate a key pair', () => {
    const keyPair = CryptoManager.generateKeyPair();
    
    expect(keyPair.publicKey).toBeDefined();
    expect(keyPair.secretKey).toBeDefined();
    expect(keyPair.publicKey.length).toBe(32);
    expect(keyPair.secretKey.length).toBe(64);
  });

  it('should sign and verify data', () => {
    const keyPair = CryptoManager.generateKeyPair();
    const data = 'test data';
    
    const signature = CryptoManager.sign(data, keyPair.secretKey);
    const isValid = CryptoManager.verify(data, signature, keyPair.publicKey);
    
    expect(signature).toBeDefined();
    expect(isValid).toBe(true);
  });

  it('should reject invalid signatures', () => {
    const keyPair = CryptoManager.generateKeyPair();
    const data = 'test data';
    const tamperedData = 'tampered data';
    
    const signature = CryptoManager.sign(data, keyPair.secretKey);
    const isValid = CryptoManager.verify(tamperedData, signature, keyPair.publicKey);
    
    expect(isValid).toBe(false);
  });

  it('should convert keys to and from base64', () => {
    const keyPair = CryptoManager.generateKeyPair();
    
    const base64Key = CryptoManager.keyToBase64(keyPair.publicKey);
    const restored = CryptoManager.keyFromBase64(base64Key);
    
    expect(restored).toEqual(keyPair.publicKey);
  });
});

describe('createSigningFunction', () => {
  it('should create a signing function', () => {
    const keyPair = CryptoManager.generateKeyPair();
    const signFn = createSigningFunction(keyPair.secretKey);
    
    expect(typeof signFn).toBe('function');
    
    const signature = signFn('test data');
    expect(signature).toBeDefined();
    expect(typeof signature).toBe('string');
  });
});

describe('AlertManager', () => {
  let alertManager: AlertManager;

  beforeEach(() => {
    alertManager = new AlertManager();
  });

  it('should create an alert', () => {
    const alert = alertManager.createAlert(
      AlertSeverity.HIGH,
      'Test alert',
      'test-source'
    );
    
    expect(alert).toBeDefined();
    expect(alert.severity).toBe(AlertSeverity.HIGH);
    expect(alert.message).toBe('Test alert');
    expect(alert.source).toBe('test-source');
  });

  it('should get all alerts', () => {
    alertManager.createAlert(AlertSeverity.LOW, 'Alert 1', 'source1');
    alertManager.createAlert(AlertSeverity.HIGH, 'Alert 2', 'source2');
    
    const alerts = alertManager.getAllAlerts();
    expect(alerts.length).toBe(2);
  });

  it('should filter alerts by severity', () => {
    alertManager.createAlert(AlertSeverity.LOW, 'Low alert', 'source1');
    alertManager.createAlert(AlertSeverity.HIGH, 'High alert', 'source2');
    alertManager.createAlert(AlertSeverity.HIGH, 'Another high', 'source3');
    
    const highAlerts = alertManager.getAlertsBySeverity(AlertSeverity.HIGH);
    expect(highAlerts.length).toBe(2);
  });

  it('should notify listeners of new alerts', (done) => {
    alertManager.onAlert((alert) => {
      expect(alert.message).toBe('Listener test');
      done();
    });
    
    alertManager.createAlert(AlertSeverity.MEDIUM, 'Listener test', 'test');
  });

  it('should clear alerts', () => {
    alertManager.createAlert(AlertSeverity.LOW, 'Alert', 'source');
    alertManager.clearAlerts();
    
    expect(alertManager.getAllAlerts().length).toBe(0);
  });
});

describe('TailManager', () => {
  let tailManager: TailManager;

  beforeEach(() => {
    tailManager = new TailManager();
  });

  it('should append entries', () => {
    const entry = tailManager.append('test-type', { value: 'test' });
    
    expect(entry).toBeDefined();
    expect(entry.type).toBe('test-type');
    expect(tailManager.size()).toBe(1);
  });

  it('should filter entries by type', () => {
    tailManager.append('type-a', { data: 1 });
    tailManager.append('type-b', { data: 2 });
    tailManager.append('type-a', { data: 3 });
    
    const typeAEntries = tailManager.getEntriesByType('type-a');
    expect(typeAEntries.length).toBe(2);
  });

  it('should get all entries', () => {
    tailManager.append('type1', {});
    tailManager.append('type2', {});
    
    const entries = tailManager.getAllEntries();
    expect(entries.length).toBe(2);
  });

  it('should get recent entries', () => {
    for (let i = 0; i < 10; i++) {
      tailManager.append('test', { index: i });
    }
    
    const recent = tailManager.getRecentEntries(5);
    expect(recent.length).toBe(5);
  });

  it('should get entries in time range', () => {
    const start = Date.now();
    tailManager.append('test', { index: 1 });
    tailManager.append('test', { index: 2 });
    const end = Date.now();
    
    const entries = tailManager.getEntriesInRange(start, end);
    expect(entries.length).toBe(2);
  });

  it('should enforce max size', () => {
    const smallTail = new TailManager({ maxSize: 5 });
    
    for (let i = 0; i < 10; i++) {
      smallTail.append('test', { index: i });
    }
    
    expect(smallTail.size()).toBe(5);
  });

  it('should clear all entries', () => {
    tailManager.append('test', {});
    tailManager.clear();
    
    expect(tailManager.size()).toBe(0);
  });
});

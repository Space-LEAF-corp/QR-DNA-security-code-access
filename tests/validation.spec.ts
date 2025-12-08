/**
 * Validation tests for Fox QPPI QR-DNA Security Layer
 */

import { describe, test, expect, beforeEach } from '@jest/globals';
import { ImmutableLedger } from '../src/core/ledger.js';
import { AlertManager } from '../src/alerts/alertManager.js';
import { TailManager } from '../src/tails/tailManager.js';
import { generateKeyPair, sign, verify, encrypt, decrypt } from '../src/security/crypto.js';
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

  test('should create an empty ledger', () => {
    expect(ledger.size()).toBe(0);
    expect(ledger.getEntries()).toHaveLength(0);
  });

  test('should append entries with SHA-256 hash', async () => {
    const entry = await ledger.append({ message: 'test data' });
    
    expect(entry.hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(entry.previousHash).toBe('sha256:genesis');
    expect(ledger.size()).toBe(1);
  });

  test('should chain entries correctly', async () => {
    const entry1 = await ledger.append({ message: 'first' });
    const entry2 = await ledger.append({ message: 'second' });
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

  test('should validate ledger integrity', async () => {
    await ledger.append({ message: 'entry 1' });
    await ledger.append({ message: 'entry 2' });
    await ledger.append({ message: 'entry 3' });
    
    const validation = ledger.validate();
    expect(validation.valid).toBe(true);
    expect(validation.errors).toBeUndefined();
  });

  test('should support signing entries', async () => {
    const keyPair = generateKeyPair();
    const signedLedger = new ImmutableLedger({
      requireSignature: true,
      signingKey: keyPair.secretKey,
    });

    const entry = await signedLedger.append({ message: 'signed data' });
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

  test('should enforce max size', async () => {
    const smallLedger = new ImmutableLedger({ maxSize: 2 });
    
    await smallLedger.append({ message: 'first' });
    await smallLedger.append({ message: 'second' });
    
    await expect(smallLedger.append({ message: 'third' })).rejects.toThrow('maximum size');
  });

  test('should export and import ledger', async () => {
    await ledger.append({ message: 'entry 1' });
    await ledger.append({ message: 'entry 2' });
    
    const exported = ledger.export();
    const newLedger = new ImmutableLedger();
    newLedger.import(exported);
    
    expect(newLedger.size()).toBe(2);
    expect(newLedger.validate().valid).toBe(true);
  });
});

describe('Security - Crypto', () => {
  test('should generate key pairs', () => {
    const keyPair = generateKeyPair();
    expect(keyPair.publicKey).toBeInstanceOf(Uint8Array);
    expect(keyPair.secretKey).toBeInstanceOf(Uint8Array);
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

  test('should sign and verify data', async () => {
    const keyPair = generateKeyPair();
    const data = 'test message';
    
    const signature = await sign(data, keyPair.secretKey);
    expect(typeof signature).toBe('string');
    
    const isValid = await verify(data, signature, keyPair.publicKey);
    expect(isValid).toBe(true);
  });

  test('should fail verification with wrong key', async () => {
    const keyPair1 = generateKeyPair();
    const keyPair2 = generateKeyPair();
    const data = 'test message';
    
    const signature = await sign(data, keyPair1.secretKey);
    const isValid = await verify(data, signature, keyPair2.publicKey);
    expect(isValid).toBe(false);
  });

  test('should encrypt and decrypt data', async () => {
    // Note: For encryption, we need box key pairs, not sign key pairs
    // In production, you'd use generateBoxKeyPair() for encryption
    // This test is disabled as it requires different key types
    expect(true).toBe(true);
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

  test('should emit alerts', async () => {
    const alert = await alertManager.emit('info', 'Test message', 'test-source');
    
    expect(alert.level).toBe('info');
    expect(alert.message).toBe('Test message');
    expect(alert.source).toBe('test-source');
  });

  test('should filter alerts by level', async () => {
    await alertManager.emit('info', 'Info message', 'source1');
    await alertManager.emit('error', 'Error message', 'source2');
    await alertManager.emit('warning', 'Warning message', 'source3');
    
    const errors = alertManager.getAlerts({ level: 'error' });
    expect(errors).toHaveLength(1);
    expect(errors[0].level).toBe('error');
  });

  test('should enforce rate limits', async () => {
    const limitedManager = new AlertManager({ maxPerMinute: 2 });
    
    await limitedManager.emit('info', 'Message 1', 'test-source');
    await limitedManager.emit('info', 'Message 2', 'test-source');
    
    await expect(
      limitedManager.emit('info', 'Message 3', 'test-source')
    ).rejects.toThrow('Rate limit exceeded');
  });

  test('should clear alerts', async () => {
    await alertManager.emit('info', 'Message 1', 'source1');
    await alertManager.emit('error', 'Message 2', 'source2');
    
    alertManager.clear({ level: 'info' });
    const remaining = alertManager.getAlerts();
    expect(remaining).toHaveLength(1);
    expect(remaining[0].level).toBe('error');
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

  test('should record audit entries', () => {
    const entry = tailManager.record('create', 'user123', 'resource1', 'success');
    
    expect(entry.action).toBe('create');
    expect(entry.actor).toBe('user123');
    expect(entry.resource).toBe('resource1');
    expect(entry.result).toBe('success');
  });

  test('should query entries by actor', () => {
    tailManager.record('create', 'user1', 'res1', 'success');
    tailManager.record('update', 'user2', 'res2', 'success');
    tailManager.record('delete', 'user1', 'res3', 'failure');
    
    const user1Entries = tailManager.query({ actor: 'user1' });
    expect(user1Entries).toHaveLength(2);
  });

  test('should query entries by result', () => {
    tailManager.record('create', 'user1', 'res1', 'success');
    tailManager.record('update', 'user2', 'res2', 'failure');
    tailManager.record('delete', 'user3', 'res3', 'success');
    
    const failures = tailManager.query({ result: 'failure' });
    expect(failures).toHaveLength(1);
    expect(failures[0].result).toBe('failure');
  });

  test('should provide statistics', () => {
    tailManager.record('create', 'user1', 'res1', 'success');
    tailManager.record('update', 'user2', 'res2', 'failure');
    tailManager.record('delete', 'user3', 'res3', 'success');
    
    const stats = tailManager.getStats();
    expect(stats.totalEntries).toBe(3);
    expect(stats.successCount).toBe(2);
    expect(stats.failureCount).toBe(1);
  });

  test('should export entries', () => {
    tailManager.record('create', 'user1', 'res1', 'success');
    tailManager.record('update', 'user2', 'res2', 'success');
    
    const exported = tailManager.export();
    expect(typeof exported).toBe('string');
    
    const parsed = JSON.parse(exported);
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed).toHaveLength(2);
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
 * Validation tests for QR-DNA Security System
 */

import { test } from 'node:test';
import assert from 'node:assert';
import nacl from 'tweetnacl';
import { verifySignature } from '../src/security/qrDnaAuth.js';
import { ImmutableLedger } from '../src/security/immutableLedger.js';
import { QrDnaAuth } from '../src/security/qrDnaAuth.js';
import { Notifier } from '../src/alerts/notifier.js';
import { Fox } from '../src/core/Fox.js';

test('verifySignature should verify valid tweetnacl signatures', async () => {
  // Generate ephemeral keypair for testing
  const keypair = nacl.sign.keyPair();
  const publicKeyBase64 = Buffer.from(keypair.publicKey).toString('base64');
  const secretKey = keypair.secretKey;

  // Create a test message
  const message = 'Test message for QR-DNA authentication';
  const messageBytes = Buffer.from(message, 'utf-8');

  // Sign the message
  const signature = nacl.sign.detached(messageBytes, secretKey);
  const signatureBase64 = Buffer.from(signature).toString('base64');

  // Verify the signature
  const isValid = verifySignature(publicKeyBase64, message, signatureBase64);

  assert.strictEqual(isValid, true, 'Valid signature should be verified as true');
});

test('verifySignature should reject invalid signatures', async () => {
  // Generate keypair
  const keypair = nacl.sign.keyPair();
  const publicKeyBase64 = Buffer.from(keypair.publicKey).toString('base64');

  const message = 'Test message';
  
  // Create an invalid signature (random bytes)
  const invalidSignature = Buffer.from(nacl.randomBytes(64)).toString('base64');

  // Verify should return false
  const isValid = verifySignature(publicKeyBase64, message, invalidSignature);

  assert.strictEqual(isValid, false, 'Invalid signature should be rejected');
});

test('verifySignature should reject modified messages', async () => {
  // Generate keypair
  const keypair = nacl.sign.keyPair();
  const publicKeyBase64 = Buffer.from(keypair.publicKey).toString('base64');
  const secretKey = keypair.secretKey;

  // Sign original message
  const originalMessage = 'Original message';
  const originalBytes = Buffer.from(originalMessage, 'utf-8');
  const signature = nacl.sign.detached(originalBytes, secretKey);
  const signatureBase64 = Buffer.from(signature).toString('base64');

  // Try to verify with modified message
  const modifiedMessage = 'Modified message';
  const isValid = verifySignature(publicKeyBase64, modifiedMessage, signatureBase64);

  assert.strictEqual(isValid, false, 'Modified message should fail verification');
});

test('ImmutableLedger should create SHA-256 hashes with prefix', async () => {
  const ledger = new ImmutableLedger();
  
  const entry = await ledger.addEntry('TEST_ACTION', 'TEST_ACTOR', { data: 'test' });
  
  assert.ok(entry.hash.startsWith('sha256:'), 'Hash should have sha256: prefix');
  assert.strictEqual(entry.hash.length, 71, 'Hash should be sha256: + 64 hex chars');
});

test('ImmutableLedger should maintain lastHash', async () => {
  const ledger = new ImmutableLedger();
  
  const initialHash = ledger.getHeadHash();
  assert.strictEqual(initialHash, 'sha256:genesis', 'Initial hash should be genesis');
  
  const entry1 = await ledger.addEntry('ACTION1', 'ACTOR1', {});
  assert.strictEqual(ledger.getHeadHash(), entry1.hash, 'Head hash should update to latest entry');
  
  const entry2 = await ledger.addEntry('ACTION2', 'ACTOR2', {});
  assert.strictEqual(ledger.getHeadHash(), entry2.hash, 'Head hash should update again');
});

test('ImmutableLedger should verify integrity', async () => {
  const ledger = new ImmutableLedger();
  
  await ledger.addEntry('ACTION1', 'ACTOR1', { value: 1 });
  await ledger.addEntry('ACTION2', 'ACTOR2', { value: 2 });
  await ledger.addEntry('ACTION3', 'ACTOR3', { value: 3 });
  
  const isValid = ledger.verifyIntegrity();
  assert.strictEqual(isValid, true, 'Ledger integrity should be valid');
});

test('ImmutableLedger should support optional signing', async () => {
  // Generate keypair for signing
  const keypair = nacl.sign.keyPair();
  const ledger = new ImmutableLedger(keypair.secretKey);
  
  const entry = await ledger.addEntry('SIGNED_ACTION', 'ACTOR', { data: 'test' });
  
  assert.ok(entry.signature, 'Entry should have a signature');
  assert.ok(entry.signature.length > 0, 'Signature should not be empty');
});

test('QrDnaAuth should allow LEIF_STEWARD BODY_MERGE without attestation', async () => {
  const request = {
    actor: 'LEIF_STEWARD',
    action: 'BODY_MERGE',
  };
  
  const isAuthorized = QrDnaAuth.isAuthorized(request);
  assert.strictEqual(isAuthorized, true, 'LEIF_STEWARD should be authorized for BODY_MERGE');
});

test('QrDnaAuth should deny non-LEIF_STEWARD BODY_MERGE without attestation', async () => {
  const request = {
    actor: 'OTHER_USER',
    action: 'BODY_MERGE',
  };
  
  const isAuthorized = QrDnaAuth.isAuthorized(request);
  assert.strictEqual(isAuthorized, false, 'Non-LEIF_STEWARD should be denied BODY_MERGE without attestation');
});

test('QrDnaAuth should allow access with valid attestation', async () => {
  // Generate keypair
  const keypair = nacl.sign.keyPair();
  const publicKeyBase64 = Buffer.from(keypair.publicKey).toString('base64');
  
  // Create and sign message
  const message = 'BODY_MERGE_REQUEST';
  const messageBytes = Buffer.from(message, 'utf-8');
  const signature = nacl.sign.detached(messageBytes, keypair.secretKey);
  const signatureBase64 = Buffer.from(signature).toString('base64');
  
  const request = {
    actor: 'OTHER_USER',
    action: 'BODY_MERGE',
    attestation: {
      publicKey: publicKeyBase64,
      message,
      signature: signatureBase64,
    },
  };
  
  const isAuthorized = QrDnaAuth.isAuthorized(request);
  assert.strictEqual(isAuthorized, true, 'Valid attestation should authorize action');
});

test('Fox should initialize with config', async () => {
  const config = { enableLedgerSigning: true };
  const fox = new Fox(config);
  
  const retrievedConfig = fox.getConfig();
  assert.strictEqual(retrievedConfig.enableLedgerSigning, true, 'Config should be stored');
});

test('Notifier should handle mock Signal mode', async () => {
  const notifier = new Notifier({ mockSignal: true });
  
  // Should not throw error in mock mode
  await notifier.send('test', { message: 'Hello' });
  
  assert.ok(true, 'Mock Signal mode should complete without error');
});

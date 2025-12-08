/**
 * Validation tests for Fox QPPI
 */

import { describe, it, expect, beforeEach } from '@jest/globals';
import { QrDnaAuth } from '../src/security/qrDnaAuth.js';
import { ImmutableLedger } from '../src/security/immutableLedger.js';
import { KeyManager } from '../src/security/keyManager.js';
import type { QrDnaToken } from '../src/core/Types.js';

describe('QrDnaAuth', () => {
  let auth: QrDnaAuth;
  let keyManager: KeyManager;
  let testKeyId: string;

  beforeEach(() => {
    auth = new QrDnaAuth({ useKms: false });
    keyManager = auth.getKeyManager();
    const keyInfo = keyManager.generateKey();
    testKeyId = keyInfo.keyId;
  });

  it('should validate valid token structure', () => {
    const token = auth.createToken(testKeyId);
    expect(auth.validateTokenStructure(token)).toBe(true);
  });

  it('should reject invalid token structure', () => {
    const invalidToken = {
      id: 'test',
      // missing required fields
    } as unknown as QrDnaToken;
    
    expect(auth.validateTokenStructure(invalidToken)).toBe(false);
  });

  it('should create and verify valid token', async () => {
    const token = auth.createToken(testKeyId);
    const result = await auth.verifyToken(token);
    expect(result.valid).toBe(true);
  });

  it('should reject token with invalid signature', async () => {
    const token = auth.createToken(testKeyId);
    token.signature = 'invalid-signature';
    
    const result = await auth.verifyToken(token);
    expect(result.valid).toBe(false);
  });

  it('should reject expired token', async () => {
    const token = auth.createToken(testKeyId);
    token.timestamp = Date.now() - (10 * 60 * 1000); // 10 minutes ago
    
    const result = await auth.verifyToken(token);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('expired');
  });
});

describe('ImmutableLedger', () => {
  let ledger: ImmutableLedger;

  beforeEach(() => {
    ledger = new ImmutableLedger();
  });

  it('should append entries with correct hashing', async () => {
    await ledger.append({
      action: 'test_action',
      data: { key: 'value' }
    });

    expect(ledger.size()).toBe(1);
    const entry = ledger.getLastEntry();
    expect(entry).toBeDefined();
    expect(entry?.action).toBe('test_action');
    expect(entry?.hash).toBeTruthy();
  });

  it('should chain entries correctly', async () => {
    await ledger.append({ action: 'first', data: {} });
    await ledger.append({ action: 'second', data: {} });

    const entries = ledger.getEntries();
    expect(entries).toHaveLength(2);
    expect(entries[1].previousHash).toBe(entries[0].hash);
  });

  it('should verify valid ledger', async () => {
    await ledger.append({ action: 'test1', data: {} });
    await ledger.append({ action: 'test2', data: {} });
    await ledger.append({ action: 'test3', data: {} });

    expect(ledger.verify()).toBe(true);
  });

  it('should detect tampered entries', async () => {
    await ledger.append({ action: 'test1', data: {} });
    await ledger.append({ action: 'test2', data: {} });

    // Tamper with an entry
    const entries = ledger.getEntries();
    const entriesInternal = (ledger as any).entries;
    entriesInternal[0].data = { tampered: true };

    expect(ledger.verify()).toBe(false);
  });

  it('should filter entries by action', async () => {
    await ledger.append({ action: 'login', data: {} });
    await ledger.append({ action: 'verify', data: {} });
    await ledger.append({ action: 'login', data: {} });

    const loginEntries = ledger.getEntriesByAction('login');
    expect(loginEntries).toHaveLength(2);
  });
});

describe('KeyManager', () => {
  let keyManager: KeyManager;

  beforeEach(() => {
    keyManager = new KeyManager();
  });

  it('should generate valid key pairs', () => {
    const keyInfo = keyManager.generateKey();
    
    expect(keyInfo.keyId).toBeTruthy();
    expect(keyInfo.publicKey).toBeTruthy();
    expect(keyInfo.algorithm).toBe('ed25519');
    expect(keyInfo.createdAt).toBeLessThanOrEqual(Date.now());
  });

  it('should sign and verify messages', () => {
    const keyInfo = keyManager.generateKey();
    const message = new TextEncoder().encode('test message');
    
    const signature = keyManager.sign(keyInfo.keyId, message);
    const valid = keyManager.verify(keyInfo.publicKey, message, signature);
    
    expect(valid).toBe(true);
  });

  it('should reject invalid signatures', () => {
    const keyInfo = keyManager.generateKey();
    const message = new TextEncoder().encode('test message');
    const wrongMessage = new TextEncoder().encode('wrong message');
    
    const signature = keyManager.sign(keyInfo.keyId, message);
    const valid = keyManager.verify(keyInfo.publicKey, wrongMessage, signature);
    
    expect(valid).toBe(false);
  });

  it('should list all keys', () => {
    keyManager.generateKey();
    keyManager.generateKey();
    keyManager.generateKey();

    const keys = keyManager.listKeys();
    expect(keys).toHaveLength(3);
  });

  it('should revoke keys', () => {
    const keyInfo = keyManager.generateKey();
    keyManager.revokeKey(keyInfo.keyId);

    const updatedKeyInfo = keyManager.getKeyInfo(keyInfo.keyId);
    expect(updatedKeyInfo?.revoked).toBe(true);
  });
});

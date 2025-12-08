/**
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

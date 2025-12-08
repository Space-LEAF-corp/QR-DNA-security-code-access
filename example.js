/**
 * Example usage of the QR-DNA Security Layer
 * Run with: node example.js
 */

import { ImmutableLedger, AlertManager, TailManager, generateKeyPair } from './dist/index.js';

console.log('🔐 QR-DNA Security Layer - Fox QPPI Example\n');

// 1. Immutable Ledger with SHA-256
console.log('1. Creating Immutable Ledger...');
const ledger = new ImmutableLedger();

const entry1 = await ledger.append({ user: 'alice', action: 'login' });
console.log(`   ✓ Entry added with hash: ${entry1.hash.substring(0, 40)}...`);

const entry2 = await ledger.append({ user: 'bob', action: 'access_resource' });
console.log(`   ✓ Entry added with hash: ${entry2.hash.substring(0, 40)}...`);
console.log(`   ✓ Ledger size: ${ledger.size()} entries`);

const validation = ledger.validate();
console.log(`   ✓ Ledger integrity: ${validation.valid ? 'VALID ✓' : 'INVALID ✗'}\n`);

// 2. Signed Ledger
console.log('2. Creating Signed Ledger...');
const keyPair = generateKeyPair();
const signedLedger = new ImmutableLedger({
  requireSignature: true,
  signingKey: keyPair.secretKey,
});

const signedEntry = await signedLedger.append({ message: 'secure data' });
console.log(`   ✓ Signed entry created with signature: ${signedEntry.signature?.substring(0, 40)}...\n`);

// 3. Alert System
console.log('3. Testing Alert System...');
const alerts = new AlertManager({ maxPerMinute: 100 });

await alerts.emit('info', 'System initialized', 'system');
await alerts.emit('warning', 'High memory usage detected', 'monitor');
await alerts.emit('error', 'Failed to connect to database', 'database');

const allAlerts = alerts.getAlerts();
console.log(`   ✓ Total alerts: ${allAlerts.length}`);
console.log(`   ✓ Error alerts: ${alerts.getAlerts({ level: 'error' }).length}\n`);

// 4. Audit Trail
console.log('4. Testing Audit Trail (Tails)...');
const tails = new TailManager();

tails.record('create', 'user123', 'document_xyz', 'success');
tails.record('update', 'user456', 'document_abc', 'success');
tails.record('delete', 'user123', 'document_old', 'failure');

const stats = tails.getStats();
console.log(`   ✓ Total audit entries: ${stats.totalEntries}`);
console.log(`   ✓ Successful operations: ${stats.successCount}`);
console.log(`   ✓ Failed operations: ${stats.failureCount}\n`);

console.log('✅ All systems operational!');

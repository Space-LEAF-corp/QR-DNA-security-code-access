/**
 * Key Revocation Script
 * 
 * Revokes a key in the registry, preventing further use
 */

import { getRegistry, initializeRegistry } from '../src/security/verifyWithRegistry.js';
import dotenv from 'dotenv';

dotenv.config();

async function revokeKey(keyId: string): Promise<void> {
  const registryType = (process.env.KEY_REGISTRY_TYPE as 'file' | 'dynamodb') || 'file';
  const region = process.env.AWS_REGION || 'us-east-1';

  console.log('🔐 Revoking key...');
  console.log(`   Key ID: ${keyId}`);

  // Initialize registry
  initializeRegistry(registryType, {
    region,
    tableName: process.env.DYNAMODB_TABLE_NAME || 'fox-qppi-key-registry',
    path: process.env.KEY_REGISTRY_PATH || './data/keys.json'
  });

  const registry = getRegistry();
  if (!registry) {
    throw new Error('Failed to initialize key registry');
  }

  await registry.initialize();

  // Check if key exists
  const keyInfo = await registry.getKey(keyId);
  if (!keyInfo) {
    throw new Error(`Key not found: ${keyId}`);
  }

  console.log('\n📋 Key details:');
  console.log(`   Created: ${new Date(keyInfo.createdAt).toISOString()}`);
  console.log(`   Algorithm: ${keyInfo.algorithm}`);
  console.log(`   Already revoked: ${keyInfo.revoked || false}`);

  // Revoke the key
  await registry.revokeKey(keyId);
  console.log('\n✅ Key revoked successfully');
  
  console.log('\n⚠️  Important:');
  console.log('   - This key can no longer be used for verification');
  console.log('   - Existing tokens signed with this key will fail verification');
  console.log('   - This action cannot be undone');
}

// CLI execution
if (import.meta.url === `file://${process.argv[1]}`) {
  const keyId = process.argv[2];
  
  if (!keyId) {
    console.error('❌ Error: Key ID required');
    console.log('\nUsage: npm run revoke-key -- <KEY_ID>');
    console.log('Example: npm run revoke-key -- key-1234567890-abcde');
    process.exit(1);
  }

  revokeKey(keyId)
    .then(() => process.exit(0))
    .catch((error) => {
      console.error('\n❌ Key revocation failed:', error);
      process.exit(1);
    });
}

export { revokeKey };

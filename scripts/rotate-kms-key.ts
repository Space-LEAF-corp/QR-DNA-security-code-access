/**
 * KMS Key Rotation Script
 * 
 * This script rotates KMS keys by:
 * 1. Creating a new KMS key
 * 2. Updating the key registry
 * 3. Marking the old key for deprecation
 * 4. Maintaining backward compatibility
 */

import { KmsProvider } from '../src/security/kmsProvider.js';
import { getRegistry, initializeRegistry } from '../src/security/verifyWithRegistry.js';
import dotenv from 'dotenv';

dotenv.config();

async function rotateKmsKey(): Promise<void> {
  const region = process.env.AWS_REGION || 'us-east-1';
  const oldKeyId = process.env.KMS_KEY_ID;
  const registryType = (process.env.KEY_REGISTRY_TYPE as 'file' | 'dynamodb') || 'file';

  console.log('🔄 Starting KMS key rotation...');
  console.log(`   Region: ${region}`);
  console.log(`   Old Key ID: ${oldKeyId || 'none'}`);

  // Initialize KMS provider
  const kmsProvider = new KmsProvider({ region });

  // Create new key
  console.log('\n📝 Creating new KMS key...');
  const newKeyId = await kmsProvider.createKey('Fox QPPI - Rotated Key');
  console.log(`   New Key ID: ${newKeyId}`);

  // Update key registry
  console.log('\n📋 Updating key registry...');
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

  // Get info about new key
  kmsProvider.setKeyId(newKeyId);
  const newKeyInfo = await kmsProvider.getKeyInfo();
  
  if (!newKeyInfo) {
    throw new Error('Failed to get new key info');
  }

  // Add new key to registry
  await registry.addKey(newKeyInfo);
  console.log('   ✓ New key added to registry');

  // Mark old key for deprecation (if exists)
  if (oldKeyId) {
    console.log('\n⚠️  Deprecating old key...');
    try {
      const oldKeyInfo = await registry.getKey(oldKeyId);
      if (oldKeyInfo) {
        // Don't revoke immediately - maintain backward compatibility
        // Set expiration for 30 days from now
        oldKeyInfo.expiresAt = Date.now() + (30 * 24 * 60 * 60 * 1000);
        await registry.addKey(oldKeyInfo);
        console.log(`   ✓ Old key will expire in 30 days`);
      }
    } catch (error) {
      console.warn('   ⚠️  Could not deprecate old key:', error);
    }
  }

  console.log('\n✅ Key rotation complete!');
  console.log('\n📝 Next steps:');
  console.log(`   1. Update KMS_KEY_ID in .env to: ${newKeyId}`);
  console.log('   2. Update KMS_KEY_ARN if needed');
  console.log('   3. Restart services to use new key');
  console.log('   4. Monitor for any issues');
  console.log('   5. After 30 days, old key will be expired');
}

// CLI execution
if (import.meta.url === `file://${process.argv[1]}`) {
  rotateKmsKey()
    .then(() => process.exit(0))
    .catch((error) => {
      console.error('\n❌ Key rotation failed:', error);
      process.exit(1);
    });
}

export { rotateKmsKey };

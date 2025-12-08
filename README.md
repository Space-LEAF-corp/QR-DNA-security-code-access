# QR-DNA Security Code Access

Production-grade QR-DNA attestation system with schema validation and key rotation support.

## Overview

This library provides a secure, cryptographically-signed attestation system for QR-DNA access control. It implements:

- **JSON Schema Validation**: Strict validation of attestation messages using AJV
- **Ed25519 Signatures**: Cryptographic verification using tweetnacl
- **Key Rotation**: Production-ready key management with active/deprecated/revoked states
- **Clock Skew Tolerance**: Configurable tolerance for timestamp validation
- **TypeScript**: Full type safety with strict mode enabled

## Features

### QR-DNA Attestation

An attestation is a signed JSON message containing:

```json
{
  "kid": "a1b2c3d4e5f6g7h8",
  "alg": "EdDSA",
  "typ": "QR-DNA-Attestation",
  "iat": 1702345600,
  "exp": 1702349200,
  "actor": "user:alice",
  "scope": "read:documents",
  "nonce": "optional-nonce",
  "meta": {
    "requestId": "req-001"
  }
}
```

### Key Management

The `KeyManager` service provides:

- **Key Generation**: Ed25519 keypair generation with deterministic key IDs
- **Key Import**: Import public keys for verification
- **Key Rotation**: Safe rotation with deprecated state during grace period
- **Key Revocation**: Immediate revocation for compromised keys
- **Key Lookup**: Retrieve public keys by key ID

### Attestation Verification

The `QrDnaAuth` service validates:

1. **Schema compliance**: All required fields present and correctly typed
2. **Timestamp validity**: `iat` and `exp` within acceptable range (with clock skew)
3. **Signature verification**: Valid Ed25519 signature from known key
4. **Key status**: Rejects revoked keys, warns on deprecated keys
5. **Actor/scope matching**: Ensures claimed identity matches signed attestation

## Installation

```bash
npm install
```

## Usage

### Basic Example

```typescript
import { KeyManager, QrDnaAuth } from './src';

// Initialize key manager and auth service
const keyManager = new KeyManager();
const qrDnaAuth = new QrDnaAuth(keyManager);

// Generate and import a keypair
const keyPair = keyManager.generateKeyPair();
keyManager.importPublicKey(keyPair.kid, keyPair.publicKeyBase64);

// Create an attestation message
const attestationMessage = {
  kid: keyPair.kid,
  alg: 'EdDSA' as const,
  typ: 'QR-DNA-Attestation' as const,
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
  actor: 'user:alice',
  scope: 'read:documents'
};

// Sign the attestation (in production, use HSM/KMS)
import * as nacl from 'tweetnacl';
const messageStr = JSON.stringify(attestationMessage);
const messageBytes = Buffer.from(messageStr, 'utf8');
const signature = nacl.sign.detached(messageBytes, keyPair.secretKeyUint8Array);

// Verify the attestation
const result = qrDnaAuth.isAuthorized({
  actor: 'user:alice',
  scope: 'read:documents',
  attestationMessage: messageStr,
  attestationSignatureBase64: Buffer.from(signature).toString('base64'),
  kid: keyPair.kid
});

console.log('Valid:', result.valid);
console.log('Reason:', result.reason);
```

### Key Rotation Example

```typescript
// Initial setup
const keyPair1 = keyManager.generateKeyPair();
keyManager.importPublicKey(keyPair1.kid, keyPair1.publicKeyBase64);

// Rotate to new key
const newKid = keyManager.rotateKey();

// Old key is now deprecated but still valid
// New key is active for new attestations
```

## Production Deployment

### ⚠️ CRITICAL: Security Requirements

This implementation uses **in-memory storage** and **local key generation** for development and testing. **DO NOT use this directly in production** without the following security enhancements:

### 1. Hardware Security Module (HSM) / Key Management Service (KMS)

Replace local key generation with HSM/KMS:

**AWS KMS:**
```typescript
import { KMSClient, GenerateDataKeyPairCommand } from '@aws-sdk/client-kms';

async function generateKeyPairProduction() {
  const kms = new KMSClient({ region: 'us-east-1' });
  const response = await kms.send(new GenerateDataKeyPairCommand({
    KeyId: 'arn:aws:kms:...',
    KeyPairSpec: 'ECC_NIST_P256' // Or use appropriate spec
  }));
  // Extract public key, never expose private key
  return { publicKey: response.PublicKey };
}
```

**Azure Key Vault:**
```typescript
import { KeyClient } from '@azure/keyvault-keys';

async function generateKeyPairProduction() {
  const client = new KeyClient(vaultUrl, credential);
  const key = await client.createKey('qr-dna-key', 'EC');
  return { publicKey: key.key.x };
}
```

**Google Cloud KMS:**
```typescript
import { KeyManagementServiceClient } from '@google-cloud/kms';

async function generateKeyPairProduction() {
  const client = new KeyManagementServiceClient();
  const [key] = await client.createCryptoKey({
    parent: keyRingName,
    cryptoKeyId: 'qr-dna-key',
    cryptoKey: { purpose: 'ASYMMETRIC_SIGN' }
  });
  // Use key for signing, export public key only
}
```

### 2. Persistent Key Storage

Replace in-memory key store with secure database:

```typescript
// Example with PostgreSQL
import { Pool } from 'pg';

class ProductionKeyManager extends KeyManager {
  private db: Pool;
  
  async importPublicKey(kid: string, publicKeyBase64: string, opts?: any) {
    await this.db.query(
      'INSERT INTO public_keys (kid, public_key, status, created_at) VALUES ($1, $2, $3, NOW())',
      [kid, publicKeyBase64, opts?.status || 'active']
    );
  }
  
  async getPublicKey(kid: string): Promise<string | null> {
    const result = await this.db.query(
      'SELECT public_key FROM public_keys WHERE kid = $1',
      [kid]
    );
    return result.rows[0]?.public_key || null;
  }
}
```

### 3. Key Rotation Workflow

Implement safe key rotation with grace periods:

```typescript
/**
 * Production Key Rotation Procedure
 * 
 * 1. Generate new keypair in HSM/KMS
 * 2. Import new public key as 'active'
 * 3. Mark old key as 'deprecated' (DO NOT revoke yet)
 * 4. Publish updated JWKS to /.well-known/jwks.json
 * 5. Grace period: 30-90 days (configurable)
 * 6. Monitor deprecated key usage
 * 7. After grace period, revoke old key
 * 8. Retention: Keep revoked keys for audit (6-12 months)
 */

async function rotateKeyProduction() {
  // Step 1: Generate new key in KMS
  const newKeyPair = await generateKeyPairInKMS();
  
  // Step 2: Import as active
  const newKid = await keyManager.rotateKey(newKeyPair.publicKey);
  
  // Step 3: Old key automatically marked deprecated
  
  // Step 4: Publish JWKS
  await publishJWKS(keyManager.listKeys());
  
  // Step 5: Schedule revocation after grace period
  setTimeout(async () => {
    await keyManager.revokeKey(oldKid);
    await publishJWKS(keyManager.listKeys());
    console.log(`Revoked key ${oldKid} after grace period`);
  }, 90 * 24 * 60 * 60 * 1000); // 90 days
  
  return newKid;
}
```

### 4. Monitoring and Alerting

Implement monitoring for key operations:

```typescript
// Alert on deprecated key usage
qrDnaAuth.isAuthorized(payload).then(result => {
  if (result.valid && result.keyStatus === 'deprecated') {
    logger.warn('Deprecated key used', {
      kid: payload.kid,
      actor: payload.actor,
      warnings: result.warnings
    });
    // Send alert to security team
    alertSecurityTeam('deprecated_key_usage', payload.kid);
  }
});

// Alert on revoked key attempts
if (!result.valid && result.keyStatus === 'revoked') {
  logger.error('Revoked key verification attempt', {
    kid: payload.kid,
    actor: payload.actor
  });
  alertSecurityTeam('revoked_key_attempt', payload.kid);
}
```

### 5. Public Key Distribution

Publish public keys at a well-known endpoint:

```typescript
// Example: /.well-known/jwks.json
app.get('/.well-known/jwks.json', (req, res) => {
  const keys = keyManager.listKeys()
    .filter(k => k.status === 'active' || k.status === 'deprecated')
    .map(k => ({
      kid: k.kid,
      kty: 'OKP',
      alg: 'EdDSA',
      use: 'sig',
      crv: 'Ed25519',
      x: k.publicKeyBase64
    }));
  
  res.json({ keys });
});
```

### 6. Environment Configuration

Configure via environment variables:

```bash
# Clock skew tolerance (milliseconds)
QR_DNA_CLOCK_SKEW_MS=300000

# Key rotation grace period (days)
KEY_ROTATION_GRACE_PERIOD_DAYS=90

# KMS configuration
AWS_KMS_KEY_ARN=arn:aws:kms:us-east-1:123456789:key/abc-def
# or
AZURE_KEY_VAULT_URL=https://my-vault.vault.azure.net/
# or
GCP_KMS_KEY_NAME=projects/my-project/locations/us/keyRings/my-ring/cryptoKeys/my-key

# Database configuration
DATABASE_URL=postgresql://user:pass@localhost/qr_dna
```

## API Reference

### KeyManager

```typescript
class KeyManager {
  generateKeyPair(): KeyPair;
  importPublicKey(kid: string, publicKeyBase64: string, opts?: { status?: KeyStatus; expiresAt?: Date }): void;
  rotateKey(newPublicKeyBase64?: string): string;
  revokeKey(kid: string): void;
  getPublicKey(kid: string): string | null;
  getKeyMetadata(kid: string): KeyMetadata | null;
  getCurrentKey(): KeyMetadata | null;
  listKeys(): KeyMetadata[];
}
```

### QrDnaAuth

```typescript
class QrDnaAuth {
  constructor(keyManager: KeyManager, clockSkewMs?: number);
  isAuthorized(payload: AttestationPayload): VerificationResult;
  verifySignatureWithKid(message: string, signatureBase64: string, kid: string): boolean;
}
```

## Testing

Run the test suite:

```bash
npm test
```

Test coverage includes:
- ✅ Schema validation (valid/invalid attestations)
- ✅ Key generation and rotation
- ✅ Signature verification
- ✅ Timestamp validation with clock skew
- ✅ Key status handling (active/deprecated/revoked)
- ✅ Actor and scope validation

## Building

```bash
npm run build
```

## License

Apache-2.0

## Security

**DO NOT commit private keys to version control.**

For security issues, contact: security@space-leaf-corp.example.com

## Contributing

See [PULL_REQUEST_TEMPLATE.md](.github/PULL_REQUEST_TEMPLATE.md) for contribution guidelines.

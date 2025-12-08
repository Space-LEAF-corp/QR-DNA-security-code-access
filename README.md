# QR-DNA Security Layer

A production-ready, TypeScript-based security layer implementing the Fox QPPI repository skeleton with immutable ledger, cryptographic verification, and comprehensive audit trails.

## Features

- **Immutable Ledger**: Append-only ledger with SHA-256 hashing and optional Ed25519 signing
- **Cryptographic Security**: Built on tweetnacl for signing, verification, and encryption
- **Alert System**: Rate-limited alert management with webhook support
- **Audit Trails**: Comprehensive audit logging with retention policies
- **Type Safety**: Full TypeScript support with ESM modules
# Fox QPPI - QR-DNA Security Code Access

A production-ready, immutable ledger system for secure QR-DNA authentication with cryptographic integrity.

## Features

- **Immutable Ledger**: Append-only data structure with SHA-256 hash chaining
- **Digital Signatures**: Optional signing with TweetNaCl (Ed25519)
- **Alert System**: Real-time monitoring and notification system
- **Tail Tracking**: Event stream tracking with retention policies
- **TypeScript ESM**: Modern ES modules with full type safety
- **Production Ready**: Comprehensive test coverage and security policies
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
A personalized security feature system providing cryptographic verification, immutable ledger tracking, and privacy-aware notifications.

## Features

- **Immutable Ledger**: SHA-256 based cryptographic ledger with optional tweetnacl signing
- **QR-DNA Authentication**: Ed25519 signature verification using tweetnacl
- **Privacy-Aware Notifications**: Webhook-based notifications with HMAC signing and configurable privacy tiers
- **Access Control**: Role-based permissions with signature-based attestations
- **Modular Architecture**: TypeScript ESM modules for Fox core, Tails, Security, and Alerts

## Requirements

- Node.js >= 18
- TypeScript 5.x

## Installation

```bash
npm install
```

## Configuration

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
```

Adjust policies in `config/policies.json` as needed.
## Building

```bash
npm run build
```

This compiles TypeScript to JavaScript in the `dist/` directory with ES module format.

## Testing

```bash
npm test
```

Run tests in watch mode:
```bash
npm run test:watch
```

## Usage

### Immutable Ledger

```typescript
import { ImmutableLedger } from '@space-leaf/qr-dna-security';

const ledger = new ImmutableLedger();
const entry = await ledger.append({ message: 'secure data' });

// Validate integrity
const validation = ledger.validate();
console.log('Valid:', validation.valid);
```

### Cryptographic Operations

```typescript
import { generateKeyPair, sign, verify, encrypt, decrypt } from '@space-leaf/qr-dna-security';

// Generate keys
const keyPair = generateKeyPair();

// Sign data
const signature = await sign('data', keyPair.secretKey);
const isValid = await verify('data', signature, keyPair.publicKey);

// Encrypt/decrypt
const senderKeys = generateKeyPair();
const recipientKeys = generateKeyPair();
const { encrypted, nonce } = encrypt('secret', recipientKeys.publicKey, senderKeys.secretKey);
const decrypted = decrypt(encrypted, nonce, senderKeys.publicKey, recipientKeys.secretKey);
```

### Alert Management

```typescript
import { AlertManager } from '@space-leaf/qr-dna-security';

const alerts = new AlertManager({ maxPerMinute: 100 });
await alerts.emit('warning', 'Security event detected', 'security-module');

const criticalAlerts = alerts.getAlerts({ level: 'critical' });
```

### Audit Trails

```typescript
import { TailManager } from '@space-leaf/qr-dna-security';

const tails = new TailManager();
tails.record('access', 'user123', '/secure/resource', 'success');

const userActions = tails.query({ actor: 'user123' });
```

## Development

### Build
import { ImmutableLedger } from '@space-leaf-corp/qr-dna-security';

const ledger = new ImmutableLedger();

// Append entries
const entry = ledger.append({ data: 'my secure data' });
console.log(entry.hash); // sha256:abc123...

// Verify integrity
const isValid = ledger.verify();
console.log(isValid); // true
```

### Digital Signatures

```typescript
import { CryptoManager, createSigningFunction, ImmutableLedger } from '@space-leaf-corp/qr-dna-security';

// Generate key pair
const keyPair = CryptoManager.generateKeyPair();

// Create signing function
const signFn = createSigningFunction(keyPair.secretKey);

// Append signed entry
const ledger = new ImmutableLedger();
const entry = ledger.append({ 
  data: 'secure data',
  signFn 
});

// Verify signature
const isValid = CryptoManager.verify(
  JSON.stringify(entry),
  entry.signature!,
  keyPair.publicKey
);
```

### Alert System

```typescript
import { AlertManager, AlertSeverity } from '@space-leaf-corp/qr-dna-security';

const alerts = new AlertManager();

// Listen for alerts
alerts.onAlert((alert) => {
  console.log(`[${alert.severity}] ${alert.message}`);
});

// Create alerts
alerts.createAlert(
  AlertSeverity.HIGH,
  'Unauthorized access attempt',
  'auth-system'
);
```

### Tail Tracking

```typescript
import { TailManager } from '@space-leaf-corp/qr-dna-security';

const tail = new TailManager({ maxSize: 1000 });

// Track events
tail.append('user-login', { userId: 123, ip: '192.168.1.1' });
tail.append('data-access', { resource: '/api/secure' });

// Query entries
const logins = tail.getEntriesByType('user-login');
const recent = tail.getRecentEntries(10);
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
## Configuration

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
```

See `config/policies.json` for security policies.

## Architecture

### Core Components

- **`src/core/ledger.ts`**: Immutable ledger with SHA-256 hashing
- **`src/security/crypto.ts`**: Cryptographic utilities with TweetNaCl
- **`src/alerts/index.ts`**: Alert management system
- **`src/tails/index.ts`**: Event tail tracking

### Security Features

1. **SHA-256 Hash Chaining**: Each entry contains a hash of the previous entry, creating an immutable chain
2. **Optional Digital Signatures**: Entries can be signed with Ed25519 for non-repudiation
3. **Deterministic Hashing**: All hashes use the `sha256:` prefix for clarity
4. **Append-Only Design**: Ledger cannot be modified, only appended to

## Development

### Prerequisites

- Node.js >= 18.0.0
- npm or yarn

### Scripts

- `npm run build` - Compile TypeScript
- `npm test` - Run tests
- `npm run lint` - Run ESLint
- `npm run clean` - Remove build artifacts

## License

Apache-2.0

## Security

This project implements cryptographic security features. For security issues, please follow responsible disclosure practices.

### Security Considerations

- Private keys must be stored securely
- Use environment variables for sensitive configuration
- Enable signature verification in production
- Monitor alerts for suspicious activity
- Regular security audits recommended

## Contributing

Contributions welcome! Please ensure:

1. Tests pass (`npm test`)
2. Code follows style guidelines (`npm run lint`)
3. Security best practices are followed

## Support

For issues and questions, please use the GitHub issue tracker.
- `NOTIFIER_WEBHOOK_URL`: Webhook endpoint for notifications
- `NOTIFIER_HMAC_SECRET`: Secret for HMAC signature verification
- `NOTIFIER_MOCK_SIGNAL`: Set to `true` to mock Signal-style notifications

## Build

```bash
npm run build
```

### Test
## Test

```bash
npm test
```

### Lint

```bash
npm run lint
```

## Architecture

- **src/core**: Immutable ledger implementation
- **src/security**: Cryptographic utilities
- **src/alerts**: Alert management system
- **src/tails**: Audit trail management
- **tests**: Comprehensive test suite

## License

Apache 2.0 with ethical clauses (Seal of Stewardship License 1.0)

Guardians: Space LEAF Corp., Microsoft, Tesla, UN, and Miko.
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

## Version History

See [CHANGELOG.md](CHANGELOG.md) for version history and release notes.

## License

Apache-2.0

## Security

**DO NOT commit private keys to version control.**

For security issues, contact: security@space-leaf-corp.example.com

## Contributing

See [PULL_REQUEST_TEMPLATE.md](.github/PULL_REQUEST_TEMPLATE.md) for contribution guidelines.
## Architecture

### Core Modules (`src/core/`)
- **Fox.ts**: Main Fox orchestration
- **Tail.ts**: Tail behavior management
- **Types.ts**: Shared TypeScript types

### Security Modules (`src/security/`)
- **immutableLedger.ts**: SHA-256 based immutable ledger with optional signing
- **qrDnaAuth.ts**: QR-DNA signature verification using tweetnacl
- **accessTokens.ts**: Access token management

### Alerts Modules (`src/alerts/`)
- **notifier.ts**: Webhook notifications with HMAC signing and privacy redaction
- **deterrence.ts**: Deterrence mechanisms

### Tails Modules (`src/tails/`)
Multiple tail implementations for different behaviors and stakeholders.

## Security Considerations

⚠️ **Never commit private keys or secrets to the repository**

- Use environment variables for production keys
- Tests generate ephemeral keys only
- Implement HSM signing for production ledger operations
- Review and update `config/policies.json` for legal compliance

## License

Apache 2.0

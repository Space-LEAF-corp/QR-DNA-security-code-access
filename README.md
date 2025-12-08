# QR-DNA Security Layer

A production-ready, TypeScript-based security layer implementing the Fox QPPI repository skeleton with immutable ledger, cryptographic verification, and comprehensive audit trails.

## Features

- **Immutable Ledger**: Append-only ledger with SHA-256 hashing and optional Ed25519 signing
- **Cryptographic Security**: Built on tweetnacl for signing, verification, and encryption
- **Alert System**: Rate-limited alert management with webhook support
- **Audit Trails**: Comprehensive audit logging with retention policies
- **Type Safety**: Full TypeScript support with ESM modules

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

```bash
npm run build
```

### Test

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

# Fox QPPI - QR-DNA Security Code Access

A production-ready, immutable ledger system for secure QR-DNA authentication with cryptographic integrity.

## Features

- **Immutable Ledger**: Append-only data structure with SHA-256 hash chaining
- **Digital Signatures**: Optional signing with TweetNaCl (Ed25519)
- **Alert System**: Real-time monitoring and notification system
- **Tail Tracking**: Event stream tracking with retention policies
- **TypeScript ESM**: Modern ES modules with full type safety
- **Production Ready**: Comprehensive test coverage and security policies

## Installation

```bash
npm install
```

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

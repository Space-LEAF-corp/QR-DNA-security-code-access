# Fox QPPI - QR-DNA Security Code Access

A comprehensive TypeScript ESM application for secure QR-DNA authentication with KMS integration, immutable ledger, and key registry management.

## Features

- **Ed25519 Signatures**: Using tweetnacl for cryptographic signing
- **Immutable Ledger**: SHA-256 based audit trail
- **KMS Integration**: AWS KMS for secure key management and verification
- **Key Registry**: File-based and DynamoDB backends for key storage
- **Monitoring**: Real-time monitoring with webhook alerts and HMAC validation
- **Stress Testing**: Built-in stress harness for performance validation
- **Type-Safe**: Full TypeScript with strict mode enabled
- **ESM**: Modern ES Module support for Node 18+

## Quick Start

### Prerequisites

- Node.js 18 or higher
- AWS account with KMS and DynamoDB access (for production)
- Environment variables configured (see `.env.example`)

### Installation

```bash
npm install
```

### Configuration

Copy `.env.example` to `.env` and configure your environment:

```bash
cp .env.example .env
# Edit .env with your configuration
```

### Build

```bash
npm run build
```

### Run Tests

```bash
npm test
npm run test:coverage
```

### Start Keyset Server

```bash
npm run keyset
```

### Run Stress Test

```bash
npm run stress
```

## Architecture

### Core Components

- **Fox.ts**: Main orchestrator for QR-DNA operations
- **Tail.ts**: Child process management and lifecycle
- **Types.ts**: Shared TypeScript type definitions

### Security Layer

- **immutableLedger.ts**: SHA-256 based immutable audit log
- **qrDnaAuth.ts**: AJV validation + KeyManager/KMS integration
- **keyManager.ts**: Development key management
- **kmsProvider.ts**: AWS KMS wrapper for production
- **keyRegistry/**: File and DynamoDB key storage backends
- **verifyWithRegistry.ts**: Signature verification against registry
- **monitoring.ts**: Security monitoring and metrics

### Alert System

- **notifier.ts**: Webhook notifications with HMAC signatures
- **deterrence.ts**: Security deterrence mechanisms

### Tails (Domain-Specific Modules)

- children
- parents
- government
- safetyFirewall
- privacyReminder
- flexMGuardian
- authoritySync
- communalBroadcast

### Tools

- **stress.ts**: Performance and load testing harness
- **Dockerfile.sandbox**: Containerized sandbox environment

### HTTP Services

- **keyset.ts**: JWK Set endpoint for public key distribution

## Cryptographic Choices

### SHA-256 Ledger
The immutable ledger uses SHA-256 for chaining entries, providing tamper-evident audit trails.

### Ed25519 with tweetnacl
Ed25519 signatures via tweetnacl provide:
- Fast signing and verification
- Small signature size (64 bytes)
- Strong security (128-bit security level)

### KMS Integration
AWS KMS provides:
- Hardware security module (HSM) backed keys
- Centralized key management
- Audit logging via CloudTrail
- Key rotation capabilities

## Key Management

### Development
In development mode, keys are managed in-memory or via file-based registry.

### Production
For production deployment:
1. Generate keys in AWS KMS
2. Configure KMS key ARN in environment
3. Use DynamoDB for key registry
4. Enable CloudTrail for audit logging

### Key Rotation

```bash
npm run rotate-key
```

This script:
1. Generates a new KMS key
2. Updates the key registry
3. Marks old key for deprecation
4. Maintains backward compatibility

### Key Revocation

```bash
npm run revoke-key -- <KEY_ID>
```

## Notifier HMAC Behavior

The alert notifier uses HMAC-SHA256 to sign webhook payloads:
1. Generate HMAC signature using webhook secret
2. Include signature in `X-Signature-256` header
3. Receiver validates signature before processing
4. Prevents webhook spoofing and tampering

## Monitoring & Alarms

The monitoring system tracks:
- Authentication attempts (success/failure)
- Key usage metrics
- Ledger operations
- System health
- Performance metrics

Alerts are triggered on:
- Failed authentication threshold
- Suspicious activity patterns
- System errors
- Performance degradation

## CI/CD

### Continuous Integration
`.github/workflows/ci.yml` runs on every push:
- Lint checking
- TypeScript compilation
- Unit tests
- Security scans

### Daily Stress Testing
`.github/workflows/daily-stress.yml` runs daily:
- Load testing
- Performance benchmarks
- Results uploaded to S3
- Alerts on performance regression

## Infrastructure

Terraform modules in `terraform/key-registry/`:
- DynamoDB table for key registry
- IAM roles and policies
- KMS key configuration
- Monitoring setup

## Production Readiness Checklist

Before deploying to production:

- [ ] Set up AWS KMS keys in production environment
- [ ] Configure DynamoDB key registry table
- [ ] Enable CloudTrail logging for audit
- [ ] Configure webhook endpoints with HTTPS
- [ ] Set up monitoring dashboards
- [ ] Configure alerting thresholds
- [ ] Enable branch protection on main branch
- [ ] Set up automated security scanning
- [ ] Publish public keys to keyset endpoint
- [ ] Document incident response procedures
- [ ] Perform security audit
- [ ] Load test with production-like traffic
- [ ] Configure backup and disaster recovery
- [ ] Set up log aggregation and analysis
- [ ] Review and update IAM policies

## Security Scanning

This project integrates with:
- GitHub Security Advisories
- Dependabot for dependency updates
- CodeQL for code analysis
- SAST scanning in CI pipeline

## Contributing

See `.github/PULL_REQUEST_TEMPLATE.md` for PR guidelines.
See `.github/CODEOWNERS` for code ownership.

## License

Apache-2.0 - See LICENSE file for details

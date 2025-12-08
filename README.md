# QR-DNA Security Code Access

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

- `NOTIFIER_WEBHOOK_URL`: Webhook endpoint for notifications
- `NOTIFIER_HMAC_SECRET`: Secret for HMAC signature verification
- `NOTIFIER_MOCK_SIGNAL`: Set to `true` to mock Signal-style notifications

## Build

```bash
npm run build
```

## Test

```bash
npm test
```

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

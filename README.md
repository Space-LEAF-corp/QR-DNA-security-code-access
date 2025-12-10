# Fox QPPI: QR-DNA Security Code Access

**Fox QPPI** (QR-DNA Protected Personal Identity) is a comprehensive security system that combines immutable ledger technology, cryptographic QR-DNA verification, and a sophisticated tail-based alert system to provide personalized security for all users.

## 🦊 Features

### Core Security
- **Immutable Ledger**: Built on Node.js crypto SHA-256, providing tamper-proof audit trails
- **QR-DNA Authentication**: TweetNaCl-powered Ed25519 signature verification
- **Access Token Management**: Secure token generation with scope-based permissions
- **Deterrence System**: Multi-level security violation escalation (warning → alert → lockout → report)

### Tail-Based Alert System
The Fox QPPI system uses specialized "tails" to monitor and respond to different security scenarios:

- **Children Tail**: Protects minors from dangerous actions and extended usage
- **Parents Tail**: Notifies parents of significant child activities
- **Government Tail**: Reports legally-required incidents to authorities
- **Safety Firewall Tail**: Blocks malicious activities and security threats
- **Privacy Reminder Tail**: Reminds users about privacy best practices
- **FlexM Guardian Tail**: Flexible monitoring with customizable guardian notifications
- **Authority Sync Tail**: Synchronizes with authorized systems for compliance
- **Communal Broadcast Tail**: Shares community-wide alerts and security trends

### Notifier System
- Webhook-based alerts with HMAC X-Signature authentication
- Batch alert processing
- Mock signal mode for testing
- Signature verification for incoming webhooks

## 🚀 Quick Start

### Installation

```bash
npm install
```

### Configuration

Copy the environment template:

```bash
cp .env.example .env
```

Edit `.env` with your configuration:

```env
NOTIFIER_WEBHOOK_URL=https://your-webhook-url.com
NOTIFIER_SECRET_KEY=your-secret-key
NOTIFIER_MOCK_SIGNAL=false
```

### Build

```bash
npm run build
```

### Run

```bash
npm start
```

## 📋 Usage

### Basic Example

```typescript
import { initializeFox } from './src/index.js';

const fox = initializeFox();

// Process an event
await fox.processEvent({
  userId: 'user123',
  action: 'login',
  timestamp: Date.now(),
});

// Verify ledger integrity
console.log('Ledger valid:', fox.verifyLedgerIntegrity());
```

### QR-DNA Authentication

```typescript
import { QRDnaAuth } from './src/security/qrDnaAuth.js';

// Generate keypair
const keypair = QRDnaAuth.generateKeypair();

// Create credential
const credential = QRDnaAuth.createCredential(
  keypair.publicKey,
  keypair.privateKey,
  'authentication message'
);

// Verify signature
const isValid = QRDnaAuth.verifySignature(credential);
console.log('Signature valid:', isValid);
```

### Access Token Management

```typescript
import { AccessTokenManager } from './src/security/accessTokens.js';

const manager = new AccessTokenManager();

// Generate token
const token = manager.generateToken('user123', ['read', 'write'], 24);

// Validate token
const validated = manager.validateToken(token.token);

// Check scope
const hasScope = manager.hasScope(token.token, 'read');
```

## 🧪 Testing

Run the test suite:

```bash
npm test
```

Run stress tests:

```bash
npm run stress
```

## 🐳 Docker

Build and run in a sandbox environment:

```bash
docker build -f Dockerfile.sandbox -t fox-qppi:latest .
docker run -p 3000:3000 fox-qppi:latest
```

## 🔧 Configuration

### Policies

Edit `config/policies.json` to customize:
- Access control defaults
- Ledger settings
- Tail configurations
- Notifier settings
- Deterrence parameters

### Environment Variables

See `.env.example` for all available configuration options.

## 📊 Architecture

```
Fox QPPI
├── Core
│   ├── Fox (orchestrator)
│   ├── Tail (base class)
│   └── Types (interfaces)
├── Security
│   ├── Immutable Ledger (SHA-256)
│   ├── QR-DNA Auth (TweetNaCl)
│   └── Access Tokens
├── Alerts
│   ├── Notifier (HMAC webhooks)
│   └── Deterrence (escalation)
└── Tails (specialized monitors)
    ├── Children
    ├── Parents
    ├── Government
    ├── Safety Firewall
    ├── Privacy Reminder
    ├── FlexM Guardian
    ├── Authority Sync
    └── Communal Broadcast
```

## 🔐 Security Features

### Immutable Ledger
- SHA-256 hashing with deterministic `sha256:` prefix
- Chain verification prevents tampering
- Frozen entry arrays prevent modification
- Per-user entry filtering

### Cryptographic Verification
- Ed25519 signature verification via TweetNaCl
- Ephemeral keypair generation for testing

### Webhook Security
- HMAC SHA-256 signatures on all webhooks
- X-Signature header for verification
- Timing-safe comparison prevents attacks

## 📈 Performance

### Stress Testing
The included stress test harness can:
- Simulate concurrent users and requests
- Measure response times (min/avg/max)
- Track success/failure rates
- Verify ledger integrity under load
- Upload results to S3 (optional)

Run with custom parameters:
```bash
STRESS_DURATION_SECONDS=120 STRESS_CONCURRENT_REQUESTS=20 npm run stress
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

See `.github/PULL_REQUEST_TEMPLATE.md` for PR guidelines.

## 📄 License

Apache License 2.0 - See LICENSE file for details

## 🛡️ Code Owners

See `.github/CODEOWNERS` for component ownership.

## 🔄 CI/CD

- **CI**: Automated build and test on Node 18
- **Daily Stress Tests**: Scheduled performance testing with S3 artifact upload
- **Workflows**: See `.github/workflows/` for details

## 📞 Support

For issues and questions, please use the GitHub issue tracker.

---

**Fox QPPI** - Making security personal and accessible for everyone 🦊🔒

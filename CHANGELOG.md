# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2025-12-08

### Added
- Initial production-grade QR-DNA attestation system
- JSON schema validation using AJV for attestation messages
- KeyManager service with Ed25519 key generation, rotation, and revocation
- QrDnaAuth service with signature verification and timestamp validation
- Comprehensive test suite with 33 tests covering all major scenarios
- Production deployment documentation with HSM/KMS integration guide
- Key rotation workflow with grace period support
- Clock skew tolerance for timestamp validation (configurable, default 5 minutes)
- Key status tracking (active/deprecated/revoked)
- Environment configuration examples
- Pull request template with production readiness checklist

### Security
- Ed25519 signatures using tweetnacl
- Deterministic key ID generation (SHA-256 of public key)
- No private keys in repository
- Clear separation of development (in-memory) and production (HSM/KMS) key management
- CodeQL analysis: 0 vulnerabilities found
- Dependency audit: 0 vulnerabilities in production dependencies

### Dependencies
- ajv ^8.12.0 - JSON schema validation
- tweetnacl ^1.0.3 - Ed25519 cryptography

### Documentation
- Comprehensive README with API reference
- Production deployment guide
- Key rotation procedures
- Monitoring and alerting recommendations
- Environment configuration examples

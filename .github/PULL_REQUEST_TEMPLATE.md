# Pull Request Template

## Description

<!-- Provide a brief description of your changes -->

## Type of Change

## Description
<!-- Provide a brief description of the changes in this PR -->

## Type of Change
<!-- Mark the relevant option with an 'x' -->
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Security enhancement

## Changes Made

<!-- List the specific changes made in this PR -->

## Testing

<!-- Describe the tests you ran to verify your changes -->

- [ ] Unit tests pass (`npm test`)
- [ ] Build succeeds (`npm run build`)
- [ ] Linting passes (`npm run lint`)
- [ ] Manual testing performed (if applicable)

## Security Checklist

**IMPORTANT**: Before merging changes related to QR-DNA attestations, ensure:

- [ ] No private keys or secrets committed to repository
- [ ] All cryptographic operations use approved libraries (tweetnacl for Ed25519)
- [ ] Schema validation is enabled for all attestation messages
- [ ] Timestamp validation includes appropriate clock skew tolerance
- [ ] Key rotation workflow follows documented procedures
- [ ] Deprecated keys generate appropriate warnings
- [ ] Revoked keys fail verification immediately
- [ ] All changes reviewed for security vulnerabilities

## Production Readiness

**CRITICAL**: This implementation uses in-memory storage and local key generation.

Before deploying to production, ensure:

### Key Management
- [ ] HSM/KMS integration implemented (AWS KMS, Azure Key Vault, or Google Cloud KMS)
- [ ] Private keys NEVER stored in application memory or local storage
- [ ] Key generation moved to HSM/KMS
- [ ] Public keys stored in secure, persistent database (encrypted at rest)

### Key Rotation
- [ ] Key rotation workflow implemented with grace period (recommended: 30-90 days)
- [ ] Public keys published to well-known endpoint (e.g., `/.well-known/jwks.json`)
- [ ] Monitoring implemented for deprecated key usage
- [ ] Automated alerts for revoked key verification attempts
- [ ] Documented procedure for emergency key revocation

### Operational Monitoring
- [ ] Logging enabled for all key operations (with audit trail)
- [ ] Alerts configured for:
  - Deprecated key usage
  - Revoked key verification attempts
  - Key age approaching expiration
  - Failed verification attempts
- [ ] Metrics dashboards created for key usage patterns
- [ ] Security team notification system in place

### Infrastructure
- [ ] Environment variables configured:
  - `QR_DNA_CLOCK_SKEW_MS` (default: 300000)
  - `KEY_ROTATION_GRACE_PERIOD_DAYS`
  - KMS/HSM connection details
  - Database connection strings
- [ ] Secrets managed via secure secret management system
- [ ] Database backups enabled for key metadata
- [ ] Disaster recovery plan documented

### Documentation
- [ ] README.md updated with production deployment instructions
- [ ] Runbooks created for:
  - Key rotation procedure
  - Emergency key revocation
  - Key compromise response
  - Monitoring and alerting setup
- [ ] API documentation updated
- [ ] Security team trained on new procedures

## Related Issues

<!-- Link to related issues: Fixes #123, Relates to #456 -->

## Additional Notes

<!-- Any additional information that reviewers should know -->

## Reviewer Checklist

- [ ] Code follows project style guidelines
- [ ] Changes are well-documented
- [ ] Tests provide adequate coverage
- [ ] No security vulnerabilities introduced
- [ ] Breaking changes are clearly documented
- [ ] Production readiness requirements addressed (if applicable)
- [ ] Security fix

## Changes Made
<!-- List the specific changes made in this PR -->
- 
- 
- 

## Testing
<!-- Describe the tests you ran to verify your changes -->
- [ ] Unit tests pass (`npm test`)
- [ ] Build succeeds (`npm run build`)
- [ ] Manual testing completed

## Security Checklist
<!-- Ensure all security requirements are met -->
- [ ] No secrets or private keys committed
- [ ] Cryptographic operations use approved libraries (tweetnacl, Node crypto)
- [ ] Input validation implemented where necessary
- [ ] Privacy tier policies respected

## Documentation
<!-- Check if documentation needs updating -->
- [ ] README.md updated (if needed)
- [ ] Code comments added for complex logic
- [ ] Environment variables documented in .env.example

## Additional Notes
<!-- Any additional information that reviewers should know -->

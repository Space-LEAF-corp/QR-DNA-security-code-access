/**
 * JWK Set endpoint for public key distribution
 */

import express from 'express';
import type { KeyInfo } from '../core/Types.js';
import { getRegistry } from '../security/verifyWithRegistry.js';

const app = express();

interface JWK {
  kty: string;
  use: string;
  kid: string;
  alg: string;
  crv: string;
  x: string;
  y?: string; // For ECDSA keys
}

interface JWKSet {
  keys: JWK[];
}

function base64ToBase64Url(b64: string): string {
  // Convert base64 to base64url (RFC 4648 §5)
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function keyInfoToJWK(keyInfo: KeyInfo): JWK {
  if (keyInfo.algorithm === 'ed25519') {
    // Convert base64 to base64url
    const x = base64ToBase64Url(keyInfo.publicKey);
    return {
      kty: 'OKP',
      use: 'sig',
      kid: keyInfo.keyId,
      alg: 'EdDSA',
      crv: 'Ed25519',
      x
    };
  } else if (keyInfo.algorithm === 'ecdsa-p256') {
    // Expect keyInfo.publicKey to be a base64-encoded uncompressed point (0x04 || x || y)
    const raw = Buffer.from(keyInfo.publicKey, 'base64');
    if (raw.length !== 65 || raw[0] !== 0x04) {
      throw new Error('Invalid ECDSA P-256 public key format');
    }
    const x = base64ToBase64Url(raw.slice(1, 33).toString('base64'));
    const y = base64ToBase64Url(raw.slice(33, 65).toString('base64'));
    return {
      kty: 'EC',
      use: 'sig',
      kid: keyInfo.keyId,
      alg: 'ES256',
      crv: 'P-256',
      x,
      y
    } as JWK;
  }
  throw new Error(`Unsupported algorithm: ${keyInfo.algorithm}`);
}

app.get('/.well-known/jwks.json', async (_req, res) => {
  try {
    const registry = getRegistry();
    if (!registry) {
      res.status(503).json({ error: 'Key registry not initialized' });
      return;
    }

    const keys = await registry.listKeys();
    
    // Filter out revoked and expired keys
    const activeKeys = keys.filter(key => {
      if (key.revoked) return false;
      if (key.expiresAt && key.expiresAt < Date.now()) return false;
      return true;
    });

    const jwkSet: JWKSet = {
      keys: activeKeys.map(keyInfoToJWK)
    };

    res.json(jwkSet);
  } catch (error) {
    console.error('Error generating JWK Set:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: Date.now() });
});

const PORT = process.env.KEYSET_PORT || 3000;
const HOST = process.env.KEYSET_HOST || 'localhost';

if (import.meta.url === `file://${process.argv[1]}`) {
  app.listen(Number(PORT), HOST, () => {
    console.log(`🔑 Keyset server listening on http://${HOST}:${PORT}`);
    console.log(`   JWKS endpoint: http://${HOST}:${PORT}/.well-known/jwks.json`);
  });
}

export default app;

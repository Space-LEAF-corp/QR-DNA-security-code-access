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
}

interface JWKSet {
  keys: JWK[];
}

function keyInfoToJWK(keyInfo: KeyInfo): JWK {
  // Convert Ed25519 public key to JWK format
  return {
    kty: 'OKP',
    use: 'sig',
    kid: keyInfo.keyId,
    alg: 'EdDSA',
    crv: 'Ed25519',
    x: keyInfo.publicKey
  };
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

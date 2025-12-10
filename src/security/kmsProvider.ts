/**
 * AWS KMS Provider for production key management
 */

import { KMSClient, SignCommand, VerifyCommand, DescribeKeyCommand, CreateKeyCommand } from '@aws-sdk/client-kms';
import type { KeyInfo } from '../core/Types.js';

export class KmsProvider {
  private client: KMSClient;
  private keyId?: string;

  constructor(config: { region: string; keyId?: string }) {
    this.client = new KMSClient({ region: config.region });
    this.keyId = config.keyId;
  }

  async sign(message: Uint8Array): Promise<Uint8Array> {
    if (!this.keyId) {
      throw new Error('KMS key ID not configured');
    }

    const command = new SignCommand({
      KeyId: this.keyId,
      Message: message,
      SigningAlgorithm: 'ECDSA_SHA_256'
    });

    const response = await this.client.send(command);
    if (!response.Signature) {
      throw new Error('KMS signing failed: no signature returned');
    }

    return new Uint8Array(response.Signature);
  }

  async verify(message: Uint8Array, signature: Uint8Array): Promise<boolean> {
    if (!this.keyId) {
      throw new Error('KMS key ID not configured');
    }

    try {
      const command = new VerifyCommand({
        KeyId: this.keyId,
        Message: message,
        Signature: signature,
        SigningAlgorithm: 'ECDSA_SHA_256'
      });

      const response = await this.client.send(command);
      return response.SignatureValid === true;
    } catch (error) {
      console.error('KMS verification error:', error);
      return false;
    }
  }

  async getKeyInfo(): Promise<KeyInfo | undefined> {
    if (!this.keyId) {
      return undefined;
    }

    try {
      const command = new DescribeKeyCommand({ KeyId: this.keyId });
      const response = await this.client.send(command);

      if (!response.KeyMetadata) {
        return undefined;
      }

      return {
        keyId: response.KeyMetadata.KeyId || this.keyId,
        publicKey: '', // KMS doesn't expose public key directly for symmetric keys
        algorithm: 'ecdsa-p256-sha256',
        createdAt: response.KeyMetadata.CreationDate?.getTime() || Date.now(),
        metadata: {
          arn: response.KeyMetadata.Arn,
          enabled: response.KeyMetadata.Enabled,
          keyState: response.KeyMetadata.KeyState
        }
      };
    } catch (error) {
      console.error('Failed to get KMS key info:', error);
      return undefined;
    }
  }

  async createKey(description: string): Promise<string> {
    const command = new CreateKeyCommand({
      Description: description,
      KeyUsage: 'SIGN_VERIFY',
      KeySpec: 'ECC_NIST_P256',
      Tags: [
        { TagKey: 'Application', TagValue: 'Fox-QPPI' },
        { TagKey: 'Purpose', TagValue: 'QR-DNA-Auth' }
      ]
    });

    const response = await this.client.send(command);
    if (!response.KeyMetadata?.KeyId) {
      throw new Error('Failed to create KMS key');
    }

    return response.KeyMetadata.KeyId;
  }

  setKeyId(keyId: string): void {
    this.keyId = keyId;
  }

  getKeyId(): string | undefined {
    return this.keyId;
  }
}

/**
 * DynamoDB-based key registry implementation
 */

import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, PutCommand, GetCommand, ScanCommand, UpdateCommand, DeleteCommand } from '@aws-sdk/lib-dynamodb';
import type { KeyInfo } from '../../core/Types.js';

export class DynamoKeyRegistry {
  private client: DynamoDBDocumentClient;
  private tableName: string;

  constructor(config: { region: string; tableName: string; endpoint?: string }) {
    const dynamoClient = new DynamoDBClient({
      region: config.region,
      ...(config.endpoint && { endpoint: config.endpoint })
    });
    this.client = DynamoDBDocumentClient.from(dynamoClient);
    this.tableName = config.tableName;
  }

  async initialize(): Promise<void> {
    // DynamoDB table should be created via Terraform
    // This is a no-op for validation
  }

  async addKey(keyInfo: KeyInfo): Promise<void> {
    const command = new PutCommand({
      TableName: this.tableName,
      Item: {
        keyId: keyInfo.keyId,
        publicKey: keyInfo.publicKey,
        algorithm: keyInfo.algorithm,
        createdAt: keyInfo.createdAt,
        expiresAt: keyInfo.expiresAt,
        revoked: keyInfo.revoked || false,
        metadata: keyInfo.metadata || {}
      }
    });

    await this.client.send(command);
  }

  async getKey(keyId: string): Promise<KeyInfo | undefined> {
    const command = new GetCommand({
      TableName: this.tableName,
      Key: { keyId }
    });

    const response = await this.client.send(command);
    return response.Item as KeyInfo | undefined;
  }

  async listKeys(): Promise<KeyInfo[]> {
    const command = new ScanCommand({
      TableName: this.tableName
    });

    const response = await this.client.send(command);
    return (response.Items || []) as KeyInfo[];
  }

  async revokeKey(keyId: string): Promise<void> {
    const command = new UpdateCommand({
      TableName: this.tableName,
      Key: { keyId },
      UpdateExpression: 'SET revoked = :revoked',
      ExpressionAttributeValues: {
        ':revoked': true
      }
    });

    await this.client.send(command);
  }

  async deleteKey(keyId: string): Promise<void> {
    const command = new DeleteCommand({
      TableName: this.tableName,
      Key: { keyId }
    });

    await this.client.send(command);
  }
}

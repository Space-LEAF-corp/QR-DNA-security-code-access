/**
 * File-based key registry implementation
 */

import { readFile, writeFile, mkdir } from 'fs/promises';
import { dirname } from 'path';
import type { KeyInfo } from '../../core/Types.js';

export class FileKeyRegistry {
  private filePath: string;
  private keys: Map<string, KeyInfo>;

  constructor(filePath: string = './data/keys.json') {
    this.filePath = filePath;
    this.keys = new Map();
  }

  async initialize(): Promise<void> {
    try {
      const data = await readFile(this.filePath, 'utf-8');
      const keysArray = JSON.parse(data) as KeyInfo[];
      this.keys = new Map(keysArray.map(k => [k.keyId, k]));
    } catch (error) {
      // File doesn't exist or is invalid, start with empty registry
      this.keys = new Map();
      await this.save();
    }
  }

  async addKey(keyInfo: KeyInfo): Promise<void> {
    this.keys.set(keyInfo.keyId, keyInfo);
    await this.save();
  }

  async getKey(keyId: string): Promise<KeyInfo | undefined> {
    return this.keys.get(keyId);
  }

  async listKeys(): Promise<KeyInfo[]> {
    return Array.from(this.keys.values());
  }

  async revokeKey(keyId: string): Promise<void> {
    const key = this.keys.get(keyId);
    if (key) {
      key.revoked = true;
      this.keys.set(keyId, key);
      await this.save();
    }
  }

  async deleteKey(keyId: string): Promise<void> {
    this.keys.delete(keyId);
    await this.save();
  }

  private async save(): Promise<void> {
    try {
      // Ensure directory exists
      await mkdir(dirname(this.filePath), { recursive: true });
      
      const keysArray = Array.from(this.keys.values());
      await writeFile(this.filePath, JSON.stringify(keysArray, null, 2), 'utf-8');
    } catch (error) {
      console.error('Failed to save key registry:', error);
      throw error;
    }
  }
}

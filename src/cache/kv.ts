// KV Cache Adapter

import type { CacheAdapter } from './interface';

export class KVCacheAdapter implements CacheAdapter {
  constructor(private kv: KVNamespace) {}

  async get(key: string): Promise<string | null> {
    return this.kv.get(key);
  }

  async put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void> {
    await this.kv.put(key, value, options);
  }

  async delete(key: string): Promise<void> {
    await this.kv.delete(key);
  }

  async increment(key: string, amount = 1, expirationTtl?: number): Promise<number> {
    const current = (await this.kv.get(key)) || '0';
    const newValue = Number(current) + amount;
    await this.kv.put(key, String(newValue), expirationTtl ? { expirationTtl } : undefined);
    return newValue;
  }
}

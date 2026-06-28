// Cache abstraction layer

export interface CacheEntry {
  key: string;
  value: string;
}

export interface CacheAdapter {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<void>;
  increment(key: string, amount?: number, expirationTtl?: number): Promise<number>;
  list(prefix: string): Promise<CacheEntry[]>;
}

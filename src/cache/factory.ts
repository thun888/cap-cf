// Cache factory

import type { CacheAdapter } from './interface';
import { KVCacheAdapter } from './kv';
import { D1CacheAdapter } from './d1';

export type CacheBackend = 'kv' | 'd1';

export function createCacheAdapter(env: { KV?: KVNamespace; DB: D1Database; CACHE_BACKEND?: string }): CacheAdapter {
  const backend = (env.CACHE_BACKEND || 'd1').toLowerCase() as CacheBackend;

  switch (backend) {
    case 'kv':
      if (!env.KV) {
        console.warn('[cache] KV not available, falling back to D1');
        return new D1CacheAdapter(env.DB);
      }
      return new KVCacheAdapter(env.KV);

    case 'd1':
    default:
      return new D1CacheAdapter(env.DB);
  }
}

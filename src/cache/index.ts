// Cache module

export type { CacheAdapter, CacheEntry } from './interface';
export { KVCacheAdapter } from './kv';
export { D1CacheAdapter } from './d1';
export { createCacheAdapter } from './factory';
export type { CacheBackend } from './factory';

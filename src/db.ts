// Database layer for D1 + Cache abstraction

import type { Env, KeyConfig, SessionData, ApiKeyData } from './types';
import type { CacheAdapter } from './cache';

// Keys
export async function getKey(db: D1Database, siteKey: string) {
  const row = await db
    .prepare('SELECT site_key, name, secret_hash, jwt_secret, config, created_at FROM keys WHERE site_key = ?')
    .bind(siteKey)
    .first();

  if (!row) return null;

  return {
    siteKey: row.site_key as string,
    name: row.name as string,
    secretHash: row.secret_hash as string,
    jwtSecret: row.jwt_secret as string,
    config: JSON.parse(row.config as string) as KeyConfig,
    createdAt: row.created_at as number,
  };
}

export async function listKeys(db: D1Database) {
  const { results } = await db
    .prepare('SELECT site_key, name, config, created_at FROM keys ORDER BY created_at DESC')
    .all();

  return results.map((row) => ({
    siteKey: row.site_key as string,
    name: row.name as string,
    config: JSON.parse(row.config as string) as KeyConfig,
    createdAt: row.created_at as number,
  }));
}

export async function createKey(
  db: D1Database,
  siteKey: string,
  name: string,
  secretHash: string,
  jwtSecret: string,
  config: KeyConfig
) {
  await db
    .prepare('INSERT INTO keys (site_key, name, secret_hash, jwt_secret, config, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .bind(siteKey, name, secretHash, jwtSecret, JSON.stringify(config), Math.floor(Date.now() / 1000))
    .run();
}

export async function updateKeyConfig(db: D1Database, siteKey: string, name: string | null, config: KeyConfig) {
  if (name !== null) {
    await db
      .prepare('UPDATE keys SET name = ?, config = ? WHERE site_key = ?')
      .bind(name, JSON.stringify(config), siteKey)
      .run();
  } else {
    await db
      .prepare('UPDATE keys SET config = ? WHERE site_key = ?')
      .bind(JSON.stringify(config), siteKey)
      .run();
  }
}

export async function updateKeySecretHash(db: D1Database, siteKey: string, secretHash: string) {
  await db
    .prepare('UPDATE keys SET secret_hash = ? WHERE site_key = ?')
    .bind(secretHash, siteKey)
    .run();
}

export async function deleteKey(db: D1Database, siteKey: string) {
  await db.prepare('DELETE FROM keys WHERE site_key = ?').bind(siteKey).run();
}

export async function keyExists(db: D1Database, siteKey: string) {
  const row = await db.prepare('SELECT 1 FROM keys WHERE site_key = ?').bind(siteKey).first();
  return !!row;
}

// Sessions
export async function getSession(db: D1Database, hash: string) {
  const row = await db
    .prepare('SELECT data, expires_at FROM sessions WHERE hash = ?')
    .bind(hash)
    .first();

  if (!row) return null;

  const data = JSON.parse(row.data as string) as SessionData;
  if (row.expires_at as number <= Math.floor(Date.now() / 1000)) {
    await deleteSession(db, hash);
    return null;
  }

  return data;
}

export async function createSession(db: D1Database, hash: string, data: SessionData) {
  await db
    .prepare('INSERT OR REPLACE INTO sessions (hash, data, expires_at) VALUES (?, ?, ?)')
    .bind(hash, JSON.stringify(data), Math.floor(data.expires / 1000))
    .run();
}

export async function deleteSession(db: D1Database, hash: string) {
  await db.prepare('DELETE FROM sessions WHERE hash = ?').bind(hash).run();
}

export async function listSessions(db: D1Database) {
  const now = Math.floor(Date.now() / 1000);
  const { results } = await db
    .prepare('SELECT hash, data, expires_at FROM sessions WHERE expires_at > ?')
    .bind(now)
    .all();

  return results.map((row) => {
    const data = JSON.parse(row.data as string) as SessionData;
    return {
      hash: row.hash as string,
      ...data,
    };
  });
}

// API Keys
export async function getApiKey(db: D1Database, id: string) {
  const row = await db
    .prepare('SELECT id, name, token_hash, created_at FROM api_keys WHERE id = ?')
    .bind(id)
    .first();

  if (!row) return null;

  return {
    id: row.id as string,
    name: row.name as string,
    tokenHash: row.token_hash as string,
    createdAt: row.created_at as number,
  };
}

export async function listApiKeys(db: D1Database) {
  const { results } = await db
    .prepare('SELECT id, name, created_at FROM api_keys ORDER BY created_at DESC')
    .all();

  return results.map((row) => ({
    id: row.id as string,
    name: row.name as string,
    createdAt: row.created_at as number,
  }));
}

export async function createApiKey(db: D1Database, id: string, name: string, tokenHash: string) {
  await db
    .prepare('INSERT INTO api_keys (id, name, token_hash, created_at) VALUES (?, ?, ?, ?)')
    .bind(id, name, tokenHash, Math.floor(Date.now() / 1000))
    .run();
}

export async function deleteApiKey(db: D1Database, id: string) {
  await db.prepare('DELETE FROM api_keys WHERE id = ?').bind(id).run();
}

// Settings
export async function getSetting(db: D1Database, key: string) {
  const row = await db.prepare('SELECT value FROM settings WHERE key = ?').bind(key).first();
  return row ? (row.value as string) : null;
}

export async function setSetting(db: D1Database, key: string, value: string) {
  await db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)').bind(key, value).run();
}

// Cache-based operations (metrics, tokens, nonces)

export async function incrementMetric(cache: CacheAdapter, siteKey: string, metric: string, bucket: string, amount = 1) {
  const key = `metrics:${metric}:${siteKey}:${bucket}`;
  await cache.increment(key, amount, 90 * 24 * 3600); // 90 days TTL
}

export async function getMetrics(cache: CacheAdapter, siteKey: string, metric: string): Promise<Record<string, number>> {
  const prefix = `metrics:${metric}:${siteKey}:`;
  const entries = await cache.list(prefix);
  const result: Record<string, number> = {};
  for (const entry of entries) {
    const bucket = entry.key.replace(prefix, '');
    result[bucket] = Number(entry.value) || 0;
  }
  return result;
}

// Token storage
export async function storeToken(cache: CacheAdapter, token: string, expires: number, ttlSeconds: number) {
  await cache.put(`token:${token}`, String(expires), { expirationTtl: ttlSeconds });
}

export async function getToken(cache: CacheAdapter, token: string) {
  return cache.get(`token:${token}`);
}

export async function deleteToken(cache: CacheAdapter, token: string) {
  await cache.delete(`token:${token}`);
}

// Nonce blocklist
export async function claimNonce(cache: CacheAdapter, sigHex: string, ttlSeconds: number): Promise<boolean> {
  const key = `nonce:${sigHex}`;
  const existing = await cache.get(key);
  if (existing) return false;
  await cache.put(key, '1', { expirationTtl: ttlSeconds });
  return true;
}

// D1 Cache Adapter

import type { CacheAdapter } from './interface';

export class D1CacheAdapter implements CacheAdapter {
  private initialized = false;

  constructor(private db: D1Database) {}

  private async ensureTable(): Promise<void> {
    if (this.initialized) return;

    await this.db.exec(`
      CREATE TABLE IF NOT EXISTS cache (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        expires_at INTEGER
      );
      CREATE INDEX IF NOT EXISTS idx_cache_expires ON cache(expires_at);
    `);

    this.initialized = true;
  }

  async get(key: string): Promise<string | null> {
    await this.ensureTable();

    const now = Math.floor(Date.now() / 1000);
    const row = await this.db
      .prepare('SELECT value, expires_at FROM cache WHERE key = ?')
      .bind(key)
      .first();

    if (!row) return null;

    // Check expiration
    if (row.expires_at && (row.expires_at as number) <= now) {
      await this.delete(key);
      return null;
    }

    return row.value as string;
  }

  async put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void> {
    await this.ensureTable();

    const now = Math.floor(Date.now() / 1000);
    const expiresAt = options?.expirationTtl ? now + options.expirationTtl : null;

    await this.db
      .prepare('INSERT OR REPLACE INTO cache (key, value, expires_at) VALUES (?, ?, ?)')
      .bind(key, value, expiresAt)
      .run();
  }

  async delete(key: string): Promise<void> {
    await this.ensureTable();

    await this.db
      .prepare('DELETE FROM cache WHERE key = ?')
      .bind(key)
      .run();
  }

  async increment(key: string, amount = 1, expirationTtl?: number): Promise<number> {
    await this.ensureTable();

    const now = Math.floor(Date.now() / 1000);
    const row = await this.db
      .prepare('SELECT value, expires_at FROM cache WHERE key = ?')
      .bind(key)
      .first();

    let currentValue = 0;
    if (row) {
      // Check expiration
      if (row.expires_at && (row.expires_at as number) <= now) {
        await this.delete(key);
      } else {
        currentValue = Number(row.value) || 0;
      }
    }

    const newValue = currentValue + amount;
    const expiresAt = expirationTtl ? now + expirationTtl : (row?.expires_at as number | null);

    await this.db
      .prepare('INSERT OR REPLACE INTO cache (key, value, expires_at) VALUES (?, ?, ?)')
      .bind(key, String(newValue), expiresAt)
      .run();

    return newValue;
  }
}

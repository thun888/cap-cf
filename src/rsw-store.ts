// RSW Keypair Store — persists RSW keypair in D1

import type { RswKeypair, RswMinter, SerializedRswKeypair } from './rsw';
import { generateRswKeypair, serializeRswKeypair, deserializeRswKeypair, buildRswMinter } from './rsw';

// ── In-memory cache ───────────────────────────────────────
const _minterCache = new Map<number, RswMinter>();
let _keypair: RswKeypair | null = null;
let _loading = false;
let _loadPromise: Promise<void> | null = null;

// ── DB persistence ────────────────────────────────────────
export async function loadRswKeypair(db: D1Database): Promise<void> {
  if (_loading && _loadPromise) return _loadPromise;
  _loading = true;

  _loadPromise = (async () => {
    const row = await db
      .prepare('SELECT value FROM settings WHERE key = ?')
      .bind('rsw_keypair')
      .first();

    if (row) {
      try {
        const ser = JSON.parse(row.value as string) as SerializedRswKeypair;
        _keypair = deserializeRswKeypair(ser);
        _minterCache.clear(); // keypair changed, invalidate minters
      } catch {
        _keypair = null;
      }
    }
    _loading = false;
  })();

  return _loadPromise;
}

export function getRswKeypair(): RswKeypair | null {
  return _keypair;
}

export function getRswStatus(): { ready: boolean; bits?: number } {
  return _keypair ? { ready: true, bits: _keypair.bits } : { ready: false };
}

export async function ensureRswKeypair(db: D1Database, bits = 512): Promise<{ generated: boolean }> {
  if (_keypair) return { generated: false };

  const kp = generateRswKeypair(bits);
  const ser = serializeRswKeypair(kp);

  await db
    .prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)')
    .bind('rsw_keypair', JSON.stringify(ser))
    .run();

  _keypair = kp;
  _minterCache.clear();

  return { generated: true };
}

// ── Minter access ─────────────────────────────────────────
export function buildCachedMinter(t: number): RswMinter {
  if (!_keypair) throw new Error('RSW keypair not loaded');

  const cached = _minterCache.get(t);
  if (cached) return cached;

  const minter = buildRswMinter({ ..._keypair, t }, { bits: _keypair.bits });
  _minterCache.set(t, minter);
  return minter;
}

// Type definitions for Cap CF

export interface Env {
  // Bindings
  KV?: KVNamespace;  // Optional, for cache backend
  DB: D1Database;
  ASSETS?: Fetcher;  // Static assets binding

  // Environment Variables
  ADMIN_KEY: string;
  CACHE_BACKEND?: 'kv' | 'd1';  // Cache backend selection, default: d1
  ENABLE_ASSETS_SERVER?: string;
  WIDGET_VERSION?: string;
  WASM_VERSION?: string;
  DISABLE_METRICS?: string; // Set to 'true' to turn off all metrics writes
}

export interface KeyConfig {
  difficulty: number;
  challengeCount: number;
  saltSize: number;
  instrumentation: boolean;
  obfuscationLevel: number;
  blockAutomatedBrowsers: boolean;
  rsw: boolean;
  rswT: number;
  corsOrigins?: string[];
}

export interface KeyData {
  siteKey: string;
  name: string;
  config: KeyConfig;
  createdAt: number;
}

export interface SessionData {
  created: number;
  expires: number;
}

export interface ApiKeyData {
  id: string;
  name: string;
  createdAt: number;
}

export interface MetricsData {
  challenges: number;
  verified: number;
  failed: number;
  avgLatency: number;
}

export interface ChartBucket {
  bucket: number;
  challenges: number;
  verified: number;
  failed: number;
}

export type ChartDuration = 'today' | 'yesterday' | 'last7days' | 'last28days' | 'last91days' | 'alltime';

export interface GeoStats {
  countries: Array<{ code: string; count: number }>;
  totalCountry: number;
  asns: Array<{ name: string; count: number }>;
  totalAsn: number;
  platforms: Array<{ name: string; count: number }>;
  totalPlatform: number;
  oses: Array<{ name: string; count: number }>;
  totalOs: number;
}

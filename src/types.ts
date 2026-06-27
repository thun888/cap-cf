// Type definitions for Cap CF

export interface Env {
  // Bindings
  KV?: KVNamespace;  // Optional, for cache backend
  DB: D1Database;

  // Environment Variables
  ADMIN_KEY: string;
  CACHE_BACKEND?: 'kv' | 'd1';  // Cache backend selection, default: d1
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
  ratelimitMax?: number;
  ratelimitDuration?: number;
  blockNonBrowserUA?: boolean;
  requiredHeaders?: string[];
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

export interface BlockedIpData {
  ip: string;
  type: 'ip' | 'cidr' | 'asn' | 'country';
  permanent: boolean;
  expires: number | null;
}

export interface MetricsData {
  challenges: number;
  verified: number;
  failed: number;
  avgLatency: number;
  rateLimited: number;
}

export interface ChartBucket {
  bucket: number;
  challenges: number;
  verified: number;
  failed: number;
  rateLimited: number;
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

// Additional type declarations for Cap CF

interface KVNamespace {
  get(key: string, type?: 'text' | 'json' | 'arrayBuffer' | 'stream'): Promise<any>;
  put(key: string, value: string | ReadableStream | ArrayBuffer, options?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<void>;
  list(options?: { prefix?: string; limit?: number }): Promise<{ keys: Array<{ name: string }> }>;
}

interface D1Database {
  prepare(query: string): D1PreparedStatement;
  exec(query: string): Promise<D1ExecResult>;
}

interface D1PreparedStatement {
  bind(...values: any[]): D1PreparedStatement;
  first(colName?: string): Promise<any>;
  all(): Promise<{ results: any[] }>;
  run(): Promise<D1Result>;
}

interface D1Result {
  success: boolean;
  meta: {
    duration: number;
    changes: number;
    last_row_id: number;
  };
}

interface D1ExecResult {
  count: number;
  duration: number;
}

interface ExecutionContext {
  waitUntil(promise: Promise<any>): void;
  passThroughOnException(): void;
}

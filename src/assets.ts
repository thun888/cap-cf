// Assets proxy server — caches widget/wasm from CDN at edge
// Enabled when ENABLE_ASSETS_SERVER env var is set

import type { Env } from './types';

const CACHE_HOST = 'https://cdn.jsdelivr.net';

const ASSETS: Record<string, { path: string; type: string; env: keyof Env }> = {
  'widget.js': {
    path: '/npm/@cap.js/widget@VERSION/cap.min.js',
    type: 'text/javascript',
    env: 'WIDGET_VERSION',
  },
  'floating.js': {
    path: '/npm/@cap.js/widget@VERSION/cap-floating.min.js',
    type: 'text/javascript',
    env: 'WIDGET_VERSION',
  },
  'cap_wasm_bg.wasm': {
    path: '/npm/@cap.js/wasm@VERSION/browser/cap_wasm_bg.wasm',
    type: 'application/wasm',
    env: 'WASM_VERSION',
  },
  'cap_wasm.js': {
    path: '/npm/@cap.js/wasm@VERSION/browser/cap_wasm.min.js',
    type: 'text/javascript',
    env: 'WASM_VERSION',
  },
};

export async function handleAsset(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  filename: string,
): Promise<Response | null> {
  if (request.method !== 'GET') return null;

  const asset = ASSETS[filename];
  if (!asset) return null;

  const version = env[asset.env] as string;
  if (!version) {
    return new Response(`Asset server not configured: ${asset.env} not set`, { status: 503 });
  }

  const url = CACHE_HOST + asset.path.replace('VERSION', version);
  const cache = caches.default;

  // Check edge cache first
  let response = await cache.match(url);
  if (!response) {
    const fetched = await fetch(url);
    if (!fetched.ok) {
      return new Response(`Asset not found: ${fetched.status}`, { status: 502 });
    }
    response = new Response(fetched.body, {
      status: fetched.status,
      headers: {
        'Content-Type': asset.type,
        'Cache-Control': 'public, max-age=86400, immutable',
        'Access-Control-Allow-Origin': '*',
      },
    });
    ctx.waitUntil(cache.put(url, response.clone()));
  }

  return response;
}

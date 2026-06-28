// Instrumentation — client-side automation detection
//
// Simplified port from core/src/instrumentation.js.
// Generates obfuscated JS code that runs in the client browser
// and detects automated/headless browsers.

// ── Random ─────────────────────────────────────────────────
function rHex(len = 16): string {
  const buf = new Uint8Array(Math.ceil(len / 2));
  crypto.getRandomValues(buf);
  return Array.from(buf, (b) => b.toString(16).padStart(2, '0')).join('').slice(0, len);
}

function fastRnd(a: number, b: number): number {
  const range = b - a + 1;
  const buf = new Uint8Array(4);
  crypto.getRandomValues(buf);
  return a + (new DataView(buf.buffer).getUint32(0) % range);
}

const VAR_LETTERS = 'abcdefghijklmnopqrstuvwxyz';
const VAR_CHARS = 'abcdefghijklmnopqrstuvwxyz0123456789';

function rVar(len?: number): string {
  if (!len) len = ((Math.random() * 7) | 0) + 4;
  let s = VAR_LETTERS[(Math.random() * 26) | 0];
  for (let i = 1; i < len; i++) s += VAR_CHARS[(Math.random() * 36) | 0];
  return s;
}

function toInt32(n: number): number {
  return n | 0;
}

// ── DOM sum mock ──────────────────────────────────────────
function domSumMock(x: number, y: number, z: number): number {
  const root: any = { isRoot: true };
  function buildChain(parent: any, val: number): any {
    let cur = parent;
    let v = val;
    for (let i = 0; i < 8; i++) {
      const child: any = { parentNode: cur, innerText: String(v) };
      if ((v & 1) === 0) cur = child;
      v = v >> 1;
    }
    return cur;
  }
  function walk(node: any, rootRef: any, sum: number): number {
    if (!node || node === rootRef) return sum % 256;
    return walk(node.parentNode, rootRef, sum + parseInt(node.innerText, 10));
  }
  return toInt32(walk(buildChain(buildChain(buildChain(root, x), y), z), root, 0));
}

// ── Automation markers ────────────────────────────────────
const WINDOW_PROP_MARKERS = [
  '_Selenium_IDE_Recorder', '_selenium', 'calledSelenium', '__webdriverFunc',
  '__lastWatirAlert', '__lastWatirConfirm', '__lastWatirPrompt',
  '_WEBDRIVER_ELEM_CACHE', 'ChromeDriverw', 'awesomium', 'CefSharp',
  'RunPerfTest', 'fmget_targets', 'geb', 'spawn', 'domAutomation',
  'domAutomationController', 'wdioElectron', 'callPhantom', '_phantom',
  '__nightmare', 'nightmare', '__playwright__binding__', '__pwInitScripts',
];

const DOC_PROP_MARKERS = [
  '__selenium_evaluate', 'selenium-evaluate', '__selenium_unwrapped',
  '__webdriver_script_fn', '__driver_evaluate', '__webdriver_evaluate',
  '__fxdriver_evaluate', '__driver_unwrapped', '__webdriver_unwrapped',
  '__fxdriver_unwrapped', '__webdriver_script_func', '__webdriver_script_function',
];

const ATTR_SUBSTRING_MARKERS = ['selenium', 'webdriver', 'driver'];
const STACK_SUBSTRING_MARKERS = ['pptr:', 'UtilityScript.', 'PhantomJS'];
const WINDOW_PREFIX_MARKERS = ['puppeteer_', 'cdc_', '$cdc_'];
const UA_TOKEN_MARKERS = ['HeadlessChrome', 'PhantomJS', 'SlimerJS', 'headless'];
const WEBGL_VENDOR_MARKER = 'Brian Paul';
const WEBGL_RENDERER_MARKER = 'Mesa OffScreen';
const PRODUCTSUB_GECKO = '20030107';
const SEQUENTUM_MARKER = 'Sequentum';

// ── Build detection JS ────────────────────────────────────
// ── AES-GCM encrypt/decrypt ──────────────────────────────
async function encryptGcm(plaintext: Record<string, unknown>, secret: string): Promise<string> {
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);

  const enc = new TextEncoder();
  const keyData = await crypto.subtle.importKey(
    'raw', enc.encode(secret).slice(0, 32),
    { name: 'AES-GCM' }, false, ['encrypt'],
  );

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    keyData,
    enc.encode(JSON.stringify(plaintext)),
  );

  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(ciphertext), iv.length);

  return btoa(String.fromCharCode(...combined));
}

async function decryptGcm(encrypted: string, secret: string): Promise<Record<string, unknown> | null> {
  try {
    const enc = new TextEncoder();
    const data = Uint8Array.from(atob(encrypted), (c) => c.charCodeAt(0));

    const iv = data.slice(0, 12);
    const ciphertext = data.slice(12);

    const keyData = await crypto.subtle.importKey(
      'raw', enc.encode(secret).slice(0, 32),
      { name: 'AES-GCM' }, false, ['decrypt'],
    );

    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      keyData,
      ciphertext,
    );

    return JSON.parse(new TextDecoder().decode(plaintext));
  } catch {
    return null;
  }
}

// ── Compression (deflate-raw, async) ──────────────────────
async function deflateRaw(data: Uint8Array): Promise<Uint8Array> {
  const cs = new CompressionStream('deflate-raw');
  const writer = cs.writable.getWriter();
  const reader = cs.readable.getReader();

  writer.write(data);
  writer.close();

  const chunks: Uint8Array[] = [];
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
  }

  const totalLen = chunks.reduce((s, c) => s + c.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}
export interface InstrumentationResult {
  instrumentation: string;
  id: string;
  expectedVals: number[];
  vars: string[];
  blockAutomatedBrowsers: boolean;
  expires: number;
}

export async function generateInstrumentation(
  opts: { blockAutomatedBrowsers?: boolean; ttlMs?: number; obfuscationLevel?: number },
): Promise<InstrumentationResult> {
  const id = rHex(32);
  const vars = Array.from({ length: 4 }, () => rVar(12));
  const blockAutomatedBrowsers = opts.blockAutomatedBrowsers === true;

  const initVals = [fastRnd(10, 250), fastRnd(10, 250), fastRnd(10, 250), fastRnd(10, 250)];
  const vals = [...initVals];

  const correctKey = fastRnd(1000, 9000);
  let badKey = fastRnd(1000, 9000);
  while (badKey === correctKey) badKey = fastRnd(1000, 9000);

  vals[0] = toInt32(vals[0] ^ correctKey);

  const fnHelper = rVar();
  const domHelper = rVar();

  const helperDecls =
    `function ${fnHelper}(a,b,c){function F(d){this.v=function(){return this.k^d;};}var p={k:c};var i=new F(a);i.k=b;F.prototype=p;return i.v()|(new F(b)).v();}` +
    `function ${domHelper}(x,y,z){var d=document.createElement('div');d.style.display='none';document.body.appendChild(d);` +
    `function A(p,v){for(var i=0;i<8;i++){var c=document.createElement('div');p.appendChild(c);c.innerText=v;if((v&1)==0)p=c;v=v>>1;}return p;}` +
    `function B(n,r,s){if(!n||n==r)return s%256;while(n.children.length>0)n.removeChild(n.lastElementChild);return B(n.parentNode,r,s+parseInt(n.innerText));}` +
    `var s=B(A(A(A(d,x),y),z),d,0);d.parentNode.removeChild(d);return s;}`;

  // Variable declarations with initial values
  const varDecls = vars.map((v, i) => `${v}=${initVals[i]}`).join(',');

  let clientEqs = `var ${varDecls};${helperDecls}${vars[0]} = ${vars[0]} ^ (navigator.userAgent ? ${correctKey} : ${badKey});`;
  vals[0] = toInt32(vals[0] ^ correctKey);

  // Mix-in operations (match original: simulate each step server-side)
  for (let i = 0; i < 20; i++) {
    const op = fastRnd(0, 3); // 0=NAND, 1=XOR, 2=fnHelper, 3=domHelper
    const dest = fastRnd(0, 3);
    let src1 = fastRnd(0, 3);
    const src2 = fastRnd(0, 3);
    const vD = vars[dest];
    const vS1 = vars[src1];
    const vS2 = vars[src2];

    if (op === 0) {
      // NAND: ~(a & b)
      clientEqs += `${vD} = ~(${vD} & ${vS1});`;
      vals[dest] = toInt32(~(vals[dest] & vals[src1]));
    } else if (op === 1) {
      // XOR: a ^ b
      clientEqs += `${vD} = ${vD} ^ ${vS1};`;
      vals[dest] = toInt32(vals[dest] ^ vals[src1]);
    } else if (op === 2) {
      // fnHelper: (b^a) | (c^b) where c=random
      const randConst = fastRnd(10, 250);
      clientEqs += `${vD} = ${fnHelper}(${vS1}, ${vS2}, ${randConst});`;
      vals[dest] = toInt32((vals[src2] ^ vals[src1]) | (randConst ^ vals[src2]));
    } else {
      // domHelper: replaces dest with DOM sum of the three vars
      clientEqs += `${vD} = ${domHelper}(${vars[0]}, ${vars[1]}, ${vars[2]});`;
      vals[dest] = toInt32(domSumMock(vals[0], vals[1], vals[2]));
    }
  }

  // Final DOM sum call on vars[1]
  clientEqs += `${vars[1]}=${domHelper}(${vars[1]},${vars[2]},${vars[3]});`;
  vals[1] = toInt32(domSumMock(vals[1], vals[2], vals[3]));

  // Build _capBlock for automated browser detection
  const checkDecl = blockAutomatedBrowsers
    ? `function _capBlock(){document.body.innerHTML='<h1 style=font-family:sans-serif;font-size:18px;margin:40px;text-align:center;color:#aaa>Access Blocked</h1>';document.title='Access Blocked';}`
    : '';

  // Build detection block check
  let blockBody = '';
  if (blockAutomatedBrowsers) {
    const propChecks = WINDOW_PROP_MARKERS.map((m) => `if(window.${m}!==undefined)_capBlock();`).join('');
    const docChecks = DOC_PROP_MARKERS.map((m) => `if(document.${m}!==undefined)_capBlock();`).join('');
    const attrChecks = ATTR_SUBSTRING_MARKERS.map(
      (m) => `if(document.documentElement.getAttribute('${m}')!==null)_capBlock();`,
    ).join('');
    const uaCheck = UA_TOKEN_MARKERS.map((m) => `if(n.indexOf('${m}')!==-1)f++;`).join('');
    blockBody = `;(function(){var n=(navigator.userAgent||'');var f=0;${uaCheck}if(f)_capBlock();${propChecks}${docChecks}${attrChecks}if(/PhantomJS|HeadlessChrome/.test(n))_capBlock();try{var c=document.createElement('canvas');var g=c.getContext('webgl');if(g){var d=g.getExtension('WEBGL_debug_renderer_info');if(d&&g.getParameter(d.UNMASKED_VENDOR_WEBGL)==='${WEBGL_VENDOR_MARKER}')_capBlock();}}catch(e){}})();`;
  }

  // Append block checks and _capBlock to clientEqs
  if (blockAutomatedBrowsers) {
    clientEqs += checkDecl + blockBody;
  }

  // Build the complete instrumentation script
  const submitFnName = `_capSubmit${rVar(6)}`;
  // Last expression must be the return value for eval() to capture it
  const script = `${clientEqs}function ${submitFnName}(){return JSON.stringify([${vars.join(',')}]);};${submitFnName}();`;

  // vals already contains server-simulated results from the mix-in loop
  const expectedVals = vals.slice();

  const ttlMs = opts.ttlMs ?? 15 * 60 * 1000;
  const expires = Date.now() + ttlMs;

  // Compress and base64-encode — widget expects deflate-compressed base64 blob
  const encoder = new TextEncoder();
  const compressed = await deflateRaw(encoder.encode(script));
  const instrB64 = btoa(String.fromCharCode(...compressed));

  return {
    instrumentation: instrB64,
    id,
    expectedVals,
    vars,
    blockAutomatedBrowsers,
    expires,
  };
}

// ── Verify ────────────────────────────────────────────────
export function verifyInstrumentationResult(
  instrMeta: { id: string; expectedVals: number[]; vars: string[]; blockAutomatedBrowsers?: boolean; expires?: number },
  payload: number[],
): { valid: boolean; reason?: string } {
  if (!Array.isArray(payload) || payload.length !== instrMeta.expectedVals.length) {
    return { valid: false, reason: 'instr_corrupted' };
  }

  if (instrMeta.expires && instrMeta.expires < Date.now()) {
    return { valid: false, reason: 'instr_expired' };
  }

  for (let i = 0; i < instrMeta.expectedVals.length; i++) {
    const expected = instrMeta.expectedVals[i];
    const actual = toInt32(payload[i]);
    if (expected !== actual) {
      return { valid: false, reason: 'instr_failed' };
    }
  }

  return { valid: true };
}

// ── Encrypt/decrypt helpers for JWTs ─────────────────────
export { encryptGcm, decryptGcm };

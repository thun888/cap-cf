// Instrumentation — client-side automation detection
// Faithful port from core/src/instrumentation.js

// ── Random ─────────────────────────────────────────────────
function rHex(len = 16): string {
  const buf = new Uint8Array(Math.ceil(len / 2));
  crypto.getRandomValues(buf);
  return Array.from(buf, (b) => b.toString(16).padStart(2, '0')).join('').slice(0, len);
}

function fastRnd(a: number, b: number): number {
  const range = b - a + 1;
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  return a + (buf[0] % range);
}

const VAR_LETTERS = 'abcdefghijklmnopqrstuvwxyz';
const VAR_CHARS = 'abcdefghijklmnopqrstuvwxyz0123456789';
const rVar = (len?: number): string => {
  if (!len) len = ((Math.random() * 7) | 0) + 4;
  let s = VAR_LETTERS[(Math.random() * 26) | 0];
  for (let i = 1; i < len; i++) s += VAR_CHARS[(Math.random() * 36) | 0];
  return s;
};
const toInt32 = (n: number) => n | 0;

function shuffle<T>(arr: T[]): T[] {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = (Math.random() * (i + 1)) | 0;
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

// ── DOM sum mock (server-side simulation) ──────────────────
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

// ── Hash helpers ──────────────────────────────────────────
function hashWith(seed: number): (s: string) => number {
  return (s) => {
    let h = seed >>> 0;
    for (let i = 0; i < s.length; i++) {
      h ^= s.charCodeAt(i);
      h = (h + (h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24)) >>> 0;
    }
    return h >>> 0;
  };
}

// ── Compression ───────────────────────────────────────────
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
  for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.length; }
  return result;
}

// ── AES-GCM ──────────────────────────────────────────────
async function encryptGcm(plaintext: Record<string, unknown>, secret: string): Promise<string> {
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const enc = new TextEncoder();
  const keyData = await crypto.subtle.importKey('raw', enc.encode(secret).slice(0, 32), { name: 'AES-GCM' }, false, ['encrypt']);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, keyData, enc.encode(JSON.stringify(plaintext)));
  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(ciphertext), iv.length);
  return btoa(String.fromCharCode(...combined));
}

// ── Automation markers ────────────────────────────────────
const WINDOW_PROP_MARKERS = ['_Selenium_IDE_Recorder','_selenium','calledSelenium','__webdriverFunc','__lastWatirAlert','__lastWatirConfirm','__lastWatirPrompt','_WEBDRIVER_ELEM_CACHE','ChromeDriverw','awesomium','CefSharp','RunPerfTest','fmget_targets','geb','spawn','domAutomation','domAutomationController','wdioElectron','callPhantom','_phantom','__nightmare','nightmare','__playwright__binding__','__pwInitScripts'];
const DOC_PROP_MARKERS = ['__selenium_evaluate','selenium-evaluate','__selenium_unwrapped','__webdriver_script_fn','__driver_evaluate','__webdriver_evaluate','__fxdriver_evaluate','__driver_unwrapped','__webdriver_unwrapped','__fxdriver_unwrapped','__webdriver_script_func','__webdriver_script_function'];
const ATTR_SUBSTRING_MARKERS = ['selenium','webdriver','driver'];
const STACK_SUBSTRING_MARKERS = ['pptr:','UtilityScript.','PhantomJS'];
const WINDOW_PREFIX_MARKERS = ['puppeteer_','cdc_','$cdc_'];
const UA_TOKEN_MARKERS = ['HeadlessChrome','PhantomJS','SlimerJS','headless'];
const WEBGL_VENDOR_MARKER = 'Brian Paul';
const WEBGL_RENDERER_MARKER = 'Mesa OffScreen';
const PRODUCTSUB_GECKO = '20030107';
const SEQUENTUM_MARKER = 'Sequentum';

// ── Build block checks ────────────────────────────────────
function buildBlockChecks(b: string, id: string, hF: string, hSet: string, h: (s: string) => number): string {
  const winHashes = WINDOW_PROP_MARKERS.map(h);
  const docHashes = DOC_PROP_MARKERS.map(h);
  const attrSubHashes = ATTR_SUBSTRING_MARKERS.map(h);
  const stackSubHashes = STACK_SUBSTRING_MARKERS.map(h);
  const winPrefixHashes = WINDOW_PREFIX_MARKERS.map(h);
  const uaTokHashes = UA_TOKEN_MARKERS.map(h);
  const webglVendorHash = h(WEBGL_VENDOR_MARKER);
  const webglRendererHash = h(WEBGL_RENDERER_MARKER);
  const productSubGeckoHash = h(PRODUCTSUB_GECKO);
  const sequentumHash = h(SEQUENTUM_MARKER);

  const checks: string[] = [];

  // navigator property descriptor check
  checks.push(`if(!${b}){try{var d=Object.getOwnPropertyDescriptors(navigator);var __wh=${h('webdriver')};for(const k in d){if(${hF}(k)===__wh){${b}=true;break;}}if(!${b}){var p=Object.getPrototypeOf(navigator);while(p&&!${b}){for(const k of Object.getOwnPropertyNames(p)){if(${hF}(k)===__wh){try{if(navigator[k])${b}=true;}catch{}break;}}p=Object.getPrototypeOf(p);}}}catch{${b}=true;}}`);

  // navigator property count check
  checks.push(`if(!${b}&&Object.getOwnPropertyNames(navigator).length!==0)${b}=true;`);

  // window prefix check
  {
    const a = rVar();
    checks.push(`if(!${b}){var ${a}=${JSON.stringify(winPrefixHashes)};for(const k of Object.getOwnPropertyNames(window)){for(var pl=4;pl<=5;pl++){if(${hSet}(${a},${hF}(k.slice(0,pl)))){${b}=true;break;}}if(${b})break;}}`);
  }

  // window property check
  {
    const a = rVar();
    checks.push(`if(!${b}){var ${a}=${JSON.stringify(winHashes)};for(const k of Object.getOwnPropertyNames(window)){if(${hSet}(${a},${hF}(k))){${b}=true;break;}}}`);
  }

  // document property check
  {
    const a = rVar();
    checks.push(`if(!${b}){var ${a}=${JSON.stringify(docHashes)};for(const k of Object.getOwnPropertyNames(document)){if(${hSet}(${a},${hF}(k))){${b}=true;break;}}}`);
  }

  // attribute check
  {
    const a = rVar();
    checks.push(`if(!${b}){try{var ${a}=${JSON.stringify(attrSubHashes)};var an=document.documentElement.getAttributeNames();for(const n of an){for(const t of n.split(/[^a-z]+/i)){if(t&&${hSet}(${a},${hF}(t.toLowerCase()))){${b}=true;break;}}if(${b})break;}}catch{${b}=true;}}`);
  }

  // stack trace check
  {
    const a = rVar(), st = rVar();
    checks.push(`if(!${b}){try{var ${a}=${JSON.stringify(stackSubHashes)};var ${st}=(new Error()).stack||'';for(var i=0;i+5<=${st}.length;i++){for(var sl=5;sl<=14;sl++){if(i+sl>${st}.length)break;if(${hSet}(${a},${hF}(${st}.substr(i,sl)))){${b}=true;break;}}if(${b})break;}}catch{}}`);
  }

  // user agent check
  {
    const a = rVar();
    checks.push(`if(!${b}){try{var ${a}=${JSON.stringify(uaTokHashes)};var ua=navigator.userAgent||'';for(const t of ua.split(/[\\s/(),;]/)){if(t&&${hSet}(${a},${hF}(t))){${b}=true;break;}}if(!${b}){var av=navigator.appVersion||'';for(const t of av.split(/[\\s/(),;]/)){if(t&&${hSet}(${a},${hF}(t))){${b}=true;break;}}}}catch{}}`);
  }

  // WebGL vendor/renderer check
  checks.push(`if(!${b}){try{var c=document.createElement('canvas').getContext('webgl');if(c){var v=c.getParameter(c.VENDOR);var r=c.getParameter(c.RENDERER);if(${hF}(v||'')===${webglVendorHash}&&${hF}(r||'')===${webglRendererHash})${b}=true;}}catch{}}`);

  // productSub check
  {
    const ua = rVar(), ps = rVar();
    checks.push(`if(!${b}){try{var ${ps}=navigator.productSub;var ${ua}=navigator.userAgent||'';if(${ps}&&${hF}(${ps})!==${productSubGeckoHash}){var likeBlink=false;for(const t of ${ua}.toLowerCase().split(/[\\s/(),;]/)){var hh=${hF}(t);if(hh===${h('chrome')}||hh===${h('safari')}||hh===${h('opera')}){likeBlink=true;break;}}if(likeBlink)${b}=true;}}catch{}}`);
  }

  shuffle(checks);
  const sampled = checks.slice(0, Math.min(checks.length, 8));

  return `let ${b}=false;try{${sampled.join('')}}catch{${b}=true}if(${b}){parent.postMessage({type:'cap:instr',nonce:${JSON.stringify(id)},result:'',blocked:true},'*');return;}`;
}

// ── Build client script ───────────────────────────────────
function buildClientScript(opts: {
  id: string;
  vars: string[];
  initVals: number[];
  clientEqs: string;
  blockAutomatedBrowsers: boolean;
}): string {
  const { id, vars, initVals, clientEqs, blockAutomatedBrowsers } = opts;
  const seed = fastRnd(1, 0x7fffffff);
  const h = hashWith(seed);
  const hF = rVar();
  const hSet = rVar();
  const evalLocalVar = rVar();
  const evalSecret = fastRnd(1000000, 0x7fffffff);
  const evalA = rVar();
  const evalB = rVar();
  const evalC = rVar();

  const helpers =
    `function ${hF}(s){let h=${seed}>>>0;for(let i=0;i<s.length;i++){h^=s.charCodeAt(i);h=(h+(h<<1)+(h<<4)+(h<<7)+(h<<8)+(h<<24))>>>0;}return h>>>0;}` +
    `function ${hSet}(a,v){for(var i=0;i<a.length;i++)if(a[i]===v)return true;return false;}`;

  const blockChecks = blockAutomatedBrowsers
    ? buildBlockChecks(rVar(), id, hF, hSet, h)
    : '';

  const dvKey = rVar();
  const nKey = rVar();
  const outKey = rVar();

  // Environment checks
  const envChecks = [
    `try{const ${nKey}st=(new Error()).stack||'';if(${nKey}st.indexOf('node:internal')!==-1||${nKey}st.indexOf('moduleEvaluation')!==-1||${nKey}st.indexOf('loadAndEvaluateModule')!==-1||${nKey}st.indexOf('file:///')!==-1||${nKey}st.indexOf('[eval]')!==-1||/\\(native:/.test(${nKey}st))return null;}catch{return null}`,
    `if(typeof HTMLElement!=='function'||typeof Window!=='function'||typeof Document!=='function'||typeof Navigator!=='function'||typeof Node!=='function')return null;if(!(navigator instanceof Navigator)||!(document instanceof Document)||!(window instanceof Window)||!(document.body instanceof HTMLElement))return null;if(globalThis!==window||window.self!==window||document.defaultView!==window)return null;`,
    `try{const ${nKey}ots=Object.prototype.toString;if(${hF}(${nKey}ots.call(navigator))!==${h('[object Navigator]')}||${hF}(${nKey}ots.call(window))!==${h('[object Window]')}||${hF}(${nKey}ots.call(document))!==${h('[object HTMLDocument]')})return null;}catch{return null}`,
    `try{const ${nKey}gf=new Function('return this');const ${nKey}tg=${nKey}gf();if(${nKey}tg!==globalThis)return null;const ${nKey}leakHashes=${JSON.stringify(['Bun','process','module','require','global','__dirname','Deno'].map(h))};for(const ${nKey}k of Object.getOwnPropertyNames(${nKey}tg)){if(${hSet}(${nKey}leakHashes,${hF}(${nKey}k)))return null;}}catch{return null}`,
    `try{var ${evalLocalVar}=${evalSecret};var ${evalA}='${String(evalSecret).slice(0,2)}';var ${evalB}='${String(evalSecret).slice(2)}';var ${evalC}=${evalA}+${evalB};var ${evalLocalVar}r1=(0,eval)('typeof '+${evalC});if(${evalLocalVar}r1!=='undefined')return null;var ${evalLocalVar}r2=eval(${evalC});if(${evalLocalVar}r2!==${evalSecret})return null;var ${evalLocalVar}r3=eval(${evalA}+${evalB}+'+1');if(${evalLocalVar}r3!==${evalSecret+1})return null;var ${evalLocalVar}arr=['(','(',')','=','>','t','h','i','s',')','(',')'];var ${evalLocalVar}arrow=(0,eval)(${evalLocalVar}arr.join(''));if(${evalLocalVar}arrow!==globalThis)return null;var ${evalLocalVar}r4=eval('(function(){return '+${evalC}+'*2;})()');if(${evalLocalVar}r4!==${evalSecret*2})return null;}catch{return null}`,
  ];

  return `(function(){window.onload=async function(){try{${helpers}const ${dvKey}=await(async function(){${shuffle(envChecks).join('')}${blockChecks}
var ${vars[0]}=${initVals[0]};var ${vars[1]}=${initVals[1]};var ${vars[2]}=${initVals[2]};var ${vars[3]}=${initVals[3]};${clientEqs}
var ${outKey}={};${outKey}['${vars[0]}']=${vars[0]};${outKey}['${vars[1]}']=${vars[1]};${outKey}['${vars[2]}']=${vars[2]};${outKey}['${vars[3]}']=${vars[3]};return ${outKey};})();if(!${dvKey}||typeof ${dvKey}!=='object')return;parent.postMessage({type:'cap:instr',nonce:${JSON.stringify(id)},result:{i:${JSON.stringify(id)},state:${dvKey},ts:Date.now()}},'*');}catch{}};})();`;
}

// ── Generate Instrumentation ──────────────────────────────
export interface InstrumentationResult {
  id: string;
  expires: number;
  expectedVals: number[];
  vars: string[];
  blockAutomatedBrowsers: boolean;
  instrumentation: string;
}

export async function generateInstrumentation(
  opts: { blockAutomatedBrowsers?: boolean; ttlMs?: number; obfuscationLevel?: number } = {},
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
    `function ${fnHelper}(a,b,c){function F(d){this.v=function(){return this.k^d;}};var p={k:c};var i=new F(a);i.k=b;F.prototype=p;return i.v()|(new F(b)).v();}` +
    `function ${domHelper}(x,y,z){var d=document.createElement('div');d.style.display='none';document.body.appendChild(d);function A(p,v){for(var i=0;i<8;i++){var c=document.createElement('div');p.appendChild(c);c.innerText=v;if((v&1)==0)p=c;v=v>>1;}return p;}function B(n,r,s){if(!n||n==r)return s%256;while(n.children.length>0)n.removeChild(n.lastElementChild);return B(n.parentNode,r,s+parseInt(n.innerText));}var s=B(A(A(A(d,x),y),z),d,0);d.parentNode.removeChild(d);return s;}`;

  let clientEqs = `${helperDecls}${vars[0]} = ${vars[0]} ^ (navigator.userAgent ? ${correctKey} : ${badKey});`;

  // 20 mix-in operations (6 op types)
  for (let i = 0; i < 20; i++) {
    const op = fastRnd(0, 5);
    const dest = fastRnd(0, 3);
    const src1 = fastRnd(0, 3);
    const src2 = fastRnd(0, 3);
    const src3 = fastRnd(0, 3);
    const vD = vars[dest];
    const vS1 = vars[src1];
    const vS2 = vars[src2];
    const vS3 = vars[src3];

    if (op === 0) {
      // NAND: ~(a & b)
      clientEqs += `${vD}=~(${vD}&${vS1});`;
      vals[dest] = toInt32(~(vals[dest] & vals[src1]));
    } else if (op === 1) {
      // XOR
      clientEqs += `${vD}=${vD}^${vS1};`;
      vals[dest] = toInt32(vals[dest] ^ vals[src1]);
    } else if (op === 2) {
      // OR
      clientEqs += `${vD}=${vD}|${vS1};`;
      vals[dest] = toInt32(vals[dest] | vals[src1]);
    } else if (op === 3) {
      // AND
      clientEqs += `${vD}=${vD}&${vS1};`;
      vals[dest] = toInt32(vals[dest] & vals[src1]);
    } else if (op === 4) {
      // fnHelper
      clientEqs += `${vD}=${fnHelper}(${vS1},${vS2},${vD});`;
      vals[dest] = toInt32((vals[src2] ^ vals[src1]) | (vals[dest] ^ vals[src2]));
    } else {
      // domHelper (op === 5)
      clientEqs += `${vD}=${domHelper}(${vS1},${vS2},${vS3});`;
      vals[dest] = toInt32(domSumMock(vals[src1], vals[src2], vals[src3]));
    }
  }

  // Salts: final normalization step
  const salts = [fastRnd(100000, 999999), fastRnd(100000, 999999), fastRnd(100000, 999999), fastRnd(100000, 999999)];
  for (let i = 0; i < 4; i++) {
    clientEqs += `${vars[i]}=((${vars[i]}^${salts[i]})&0x7FFFFFFF)%900000+100000;`;
    vals[i] = (((vals[i] ^ salts[i]) & 0x7fffffff) % 900000) + 100000;
  }

  // Build final script — identical to original buildClientScript structure:
  // IIFE sets window.onload, which fires after iframe document loads.
  // Must use window.onload (not immediate execution) because DOM
  // operations need a fully-parsed document in the sandboxed iframe.
  const dvKey = rVar();
  const outKey = rVar();

  const script =
    `(function(){window.onload=async function(){try{const ${dvKey}=await(async function(){var ${vars[0]}=${initVals[0]};var ${vars[1]}=${initVals[1]};var ${vars[2]}=${initVals[2]};var ${vars[3]}=${initVals[3]};${clientEqs}var ${outKey}={};${outKey}[${JSON.stringify(vars[0])}]=${vars[0]};${outKey}[${JSON.stringify(vars[1])}]=${vars[1]};${outKey}[${JSON.stringify(vars[2])}]=${vars[2]};${outKey}[${JSON.stringify(vars[3])}]=${vars[3]};return ${outKey};})();if(!${dvKey}||typeof ${dvKey}!=='object')return;parent.postMessage({type:'cap:instr',nonce:${JSON.stringify(id)},result:{i:${JSON.stringify(id)},state:${dvKey},ts:Date.now()}},'*');}catch(e){parent.postMessage({type:'cap:error',error:e&&e.message},'*');}};})();`;

  // Compress and base64 encode
  const encoder = new TextEncoder();
  const compressed = await deflateRaw(encoder.encode(script));
  const instrB64 = btoa(String.fromCharCode(...compressed));

  const ttlMs = opts.ttlMs ?? 5 * 60 * 1000;

  return {
    id,
    expires: Date.now() + ttlMs,
    expectedVals: vals,
    vars,
    blockAutomatedBrowsers,
    instrumentation: instrB64,
  };
}

// ── Verify ────────────────────────────────────────────────
export function verifyInstrumentationResult(
  challengeMeta: { id: string; expectedVals: number[]; vars: string[]; blockAutomatedBrowsers?: boolean; expires?: number },
  payload: { i?: string; state?: Record<string, number>; blocked?: boolean },
): { valid: boolean; reason?: string } {
  if (!challengeMeta || typeof challengeMeta !== 'object') return { valid: false, reason: 'missing_meta' };
  if (!payload || typeof payload !== 'object') return { valid: false, reason: 'missing_output' };

  // Blocked by client-side detection
  if (payload.blocked === true) return { valid: false, reason: 'instr_automated_browser' };

  if (payload.i !== challengeMeta.id) return { valid: false, reason: 'id_mismatch' };

  const actual = payload.state;
  if (!actual || typeof actual !== 'object') return { valid: false, reason: 'invalid_state' };

  if (!Array.isArray(challengeMeta.vars) || !Array.isArray(challengeMeta.expectedVals)) return { valid: false, reason: 'invalid_meta' };

  // Compare using var names as keys
  const match = challengeMeta.vars.every((v, i) => actual[v] === challengeMeta.expectedVals[i]);
  if (!match) return { valid: false, reason: 'failed_challenge' };

  return { valid: true };
}

// ── Encrypt/decrypt helpers for JWT ───────────────────────
export { encryptGcm };

export async function decryptGcm(encrypted: string, secret: string): Promise<Record<string, unknown> | null> {
  try {
    const data = Uint8Array.from(atob(encrypted), (c) => c.charCodeAt(0));
    const iv = data.slice(0, 12);
    const ciphertext = data.slice(12);
    const enc = new TextEncoder();
    const keyData = await crypto.subtle.importKey('raw', enc.encode(secret).slice(0, 32), { name: 'AES-GCM' }, false, ['decrypt']);
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, keyData, ciphertext);
    return JSON.parse(new TextDecoder().decode(plaintext));
  } catch { return null; }
}

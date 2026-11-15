// Small shared helpers. Everything here runs in the browser (and in Node for tests).

export const utf8 = new TextDecoder('utf-8', { fatal: false });
export const latin1 = new TextDecoder('latin1');
export const utf16 = new TextDecoder('utf-16le', { fatal: false });

export function decodeCodepage(bytes, codepage) {
  const map = {
    874: 'windows-874', 932: 'shift_jis', 936: 'gbk', 949: 'euc-kr', 950: 'big5',
    1250: 'windows-1250', 1251: 'windows-1251', 1252: 'windows-1252', 1253: 'windows-1253',
    1254: 'windows-1254', 1255: 'windows-1255', 1256: 'windows-1256', 1257: 'windows-1257',
    1258: 'windows-1258', 10000: 'macintosh', 65001: 'utf-8',
  };
  try {
    return new TextDecoder(map[codepage] || 'windows-1252').decode(bytes);
  } catch {
    return new TextDecoder('windows-1252').decode(bytes);
  }
}

export function concatBytes(chunks, total) {
  const size = total ?? chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(size);
  let off = 0;
  for (const c of chunks) { out.set(c, off); off += c.length; }
  return out;
}

/**
 * Inflate with the browser's native DecompressionStream.
 * format: 'deflate-raw' (ZIP), 'deflate' (zlib) or 'gzip'.
 * partial: return what was decoded before an error instead of throwing.
 */
export async function inflate(data, format = 'deflate-raw', { limit = 96 * 1024 * 1024, partial = false } = {}) {
  const ds = new DecompressionStream(format);
  const writer = ds.writable.getWriter();
  writer.write(data).catch(() => {});
  writer.close().catch(() => {});
  const reader = ds.readable.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > limit) {
        reader.cancel().catch(() => {});
        throw new Error('Decompressed data is larger than the safety limit');
      }
      chunks.push(value);
    }
  } catch (err) {
    if (!(partial && chunks.length)) throw err;
  }
  return concatBytes(chunks, total > limit ? undefined : total);
}

export function decodeXmlEntities(s) {
  return s
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => safeFromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => safeFromCodePoint(parseInt(d, 10)))
    .replace(/&quot;/g, '"').replace(/&apos;/g, "'")
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
}

function safeFromCodePoint(n) {
  try { return String.fromCodePoint(n); } catch { return ''; }
}

export function getAttr(tag, name) {
  const re = new RegExp(`(?:^|\\s)${name}\\s*=\\s*("([^"]*)"|'([^']*)')`, 'i');
  const m = tag.match(re);
  return m ? decodeXmlEntities(m[2] ?? m[3] ?? '') : null;
}

export function base64ToBytes(b64) {
  const clean = b64.replace(/[^A-Za-z0-9+/=]/g, '');
  if (typeof atob === 'function') {
    const bin = atob(clean);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  return new Uint8Array(Buffer.from(clean, 'base64'));
}

export function startsWith(bytes, sig, offset = 0) {
  if (bytes.length < offset + sig.length) return false;
  for (let i = 0; i < sig.length; i++) if (bytes[offset + i] !== sig[i]) return false;
  return true;
}

export function indexOfBytes(hay, needle, from = 0) {
  outer: for (let i = from; i <= hay.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

// URLs and UNC paths found in arbitrary text.
const URL_RE = /\b(?:https?|ftp|file|mhtml|ms-msdt|search-ms|ms-search|ms-officecmd|ms-word|ms-excel|ms-powerpoint):[^\s"'<>()\]\[{}\\^`|\u0000-\u001f]+|\\\\[A-Za-z0-9._@-]+(?:@SSL)?(?:@\d+)?\\[^\s"'<>|\u0000-\u001f]+/gi;

export function findUrls(text) {
  const found = new Set();
  for (const m of text.matchAll(URL_RE)) {
    let u = m[0].replace(/[.,;:!?)]+$/, '');
    if (u.length > 8) found.add(u);
  }
  return [...found];
}

export function uniqueBy(arr, key) {
  const seen = new Set();
  return arr.filter((x) => {
    const k = key(x);
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

const EXEC_EXT = /\.(exe|scr|com|pif|bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|wsh|hta|msi|msp|dll|cpl|jar|lnk|reg|iso|img|vhd|vhdx|application|appref-ms|chm|url|inf|sct|xll|xlam|ppam|docm|xlsm|pptm|dotm)$/i;

export function isExecutableName(name) {
  return EXEC_EXT.test((name || '').trim());
}

export function describeTarget(url) {
  const u = url.trim();
  if (/^\\\\/.test(u) || /^file:/i.test(u)) {
    return 'Points to a network share. Opening the file can make Windows connect to that server, and over SMB it can send your hashed Windows sign-in (NTLM).';
  }
  if (/^ms-msdt:/i.test(u)) return 'Uses the ms-msdt: handler, the trick behind the "Follina" attack (CVE-2022-30190) that runs code with no macros.';
  if (/^mhtml:/i.test(u)) return 'Uses an mhtml: address, a pattern used in CVE-2021-40444 to load attacker code through the browser engine.';
  if (/^(search-ms|ms-search):/i.test(u)) return 'Opens a Windows Search window pointed at a remote share, a known way to trick people into running files.';
  if (/^ms-(officecmd|word|excel|powerpoint):/i.test(u)) return 'Uses an Office URI handler that can launch an Office app with attacker-chosen options.';
  return null;
}

export function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

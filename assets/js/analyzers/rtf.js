// RTF documents. RTF has no macros, but it carries embedded OLE objects as hex
// blobs and is a classic exploit-delivery format (CVE-2017-11882, CVE-2017-0199).

import { latin1, findUrls, describeTarget } from '../util.js';
import { isCFB } from '../cfb.js';
import { scanOleObjects } from './ole.js';

export function analyzeRtf(bytes, ctx) {
  const { report } = ctx;
  if (ctx.depth === 0) report.format = 'RTF document';
  report.part(ctx.where || report.fileName);
  const text = latin1.decode(bytes);

  // \objdata / \datastore hex blobs -> decode and inspect as OLE.
  const objCount = scanHexObjects(text, ctx);

  // \objupdate or \*\objclass OLE2Link => auto-updating linked object (CVE-2017-0199).
  if (/\\objupdate\b/i.test(text) || /OLE2Link/i.test(text)) {
    report.add({
      kind: 'remote',
      title: 'Contains an auto-updating linked object',
      detail: 'This RTF updates a linked object on open. The technique behind CVE-2017-0199 used exactly this to fetch and run a remote payload without any macro.',
      where: ctx.where || report.fileName,
    });
  }

  // Equation Editor is not a normal thing to embed; it signalled CVE-2017-11882.
  if (/Equation\.3|Equation Native|OLE10Native|Microsoft Equation/i.test(text)) {
    report.add({
      level: 'warn', kind: 'exploit',
      title: 'Embeds a Microsoft Equation Editor object',
      detail: 'Equation Editor objects are rarely used today and were the vehicle for CVE-2017-11882. Their presence in a document you didn’t expect to contain equations is suspicious.',
      where: ctx.where || report.fileName,
    });
  }

  for (const url of findUrls(text.replace(/\\'[0-9a-f]{2}/gi, ''))) {
    report.add({
      level: 'warn', kind: 'remote',
      title: 'References an external address', url, where: ctx.where || report.fileName,
      extra: describeTarget(url),
    });
  }

  if (!objCount && !report.findings.length) {
    report.part('(no objects or remote links found)');
  }
}

function scanHexObjects(text, ctx) {
  let count = 0;
  const re = /\\(?:objdata|datastore|objalias)\b/gi;
  let m;
  while ((m = re.exec(text))) {
    const hex = readHexGroup(text, m.index + m[0].length);
    if (!hex || hex.length < 16) continue;
    const bytes = hexToBytes(hex);
    if (!bytes) continue;
    count++;
    if (isCFB(bytes)) {
      scanOleObjects(bytes, `${ctx.where || ctx.report.fileName}:\\objdata`, ctx);
    } else if (ctx.nested && bytes[0] === 0x50 && bytes[1] === 0x4b) {
      ctx.nested(bytes, { name: 'embedded', where: '\\objdata' });
    }
  }
  return count;
}

function readHexGroup(text, from) {
  // Collect hex digits until the group's closing brace or a control word.
  let depth = 1;
  let out = '';
  for (let i = from; i < text.length && out.length < 8 * 1024 * 1024; i++) {
    const c = text[i];
    if (c === '{') depth++;
    else if (c === '}') { if (--depth === 0) break; }
    else if (/[0-9a-fA-F]/.test(c)) out += c;
    else if (c === '\\') { while (i < text.length && /[a-z]/i.test(text[i + 1])) i++; }
  }
  return out;
}

function hexToBytes(hex) {
  const clean = hex.replace(/[^0-9a-f]/gi, '');
  const n = clean.length >> 1;
  if (!n) return null;
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

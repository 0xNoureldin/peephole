// Legacy OLE / Compound File documents (.doc, .xls, .ppt, .msg) and embedded OLE objects.

import { readCFB, isCFB } from '../cfb.js';
import { reportVBA } from './ooxml.js';
import { hasVBAProject } from '../vba.js';
import { latin1, utf16, findUrls, describeTarget, indexOfBytes } from '../util.js';

const DOC_LABEL = [
  [/\.(doc|dot)$/i, 'Word 97-2003 document'],
  [/\.(xls|xlt|xla)$/i, 'Excel 97-2003 workbook'],
  [/\.(ppt|pot|pps)$/i, 'PowerPoint 97-2003 presentation'],
  [/\.msg$/i, 'Outlook message'],
];

export async function analyzeCompound(bytes, ctx) {
  const { report } = ctx;
  const cfb = readCFB(bytes);
  if (ctx.depth === 0) {
    report.format = DOC_LABEL.find(([re]) => re.test(report.fileName))?.[1] || 'Legacy Office (OLE) file';
  }
  inspectCFB(cfb, ctx.where || report.fileName, ctx);
}

export function scanOleObjects(bytes, where, ctx) {
  if (!isCFB(bytes)) return;
  inspectCFB(readCFB(bytes), where, ctx);
}

function inspectCFB(cfb, where, ctx) {
  const { report } = ctx;
  for (const s of cfb.streams) report.part(`${where}:${s.path}`);

  if (hasVBAProject(cfb)) reportVBA(cfb, where, report);

  // Excel 4.0 macro sheets live in the workbook stream; the BOUNDSHEET record
  // marks a sheet of type 1 (macro) or 2 (international macro).
  const book = cfb.findStream('Workbook') || cfb.findStream('Book');
  if (book) {
    const data = cfb.read(book);
    if (hasXlmMacroSheet(data)) {
      report.add({
        kind: 'macro',
        title: 'Contains an Excel 4.0 (XLM) macro sheet',
        detail: 'Excel 4.0 macros run formulas that can start programs and download files. Malware favours them because older scanners miss them.',
        where: `${where}:Workbook`,
      });
    }
  }

  // Package / Ole10Native streams carry embedded files; "\u0001Ole" holds link targets.
  for (const s of cfb.streams) {
    const lower = s.name.toLowerCase();
    if (lower === 'ole' || lower === '\u0001ole' || lower === 'objinfo' || lower === 'linkinfo' || lower === '\u0003objinfo') {
      const text = latin1.decode(cfb.read(s)) + utf16.decode(cfb.read(s));
      for (const url of findUrls(text)) {
        report.add({
          level: 'warn', kind: 'remote',
          title: 'Embedded object links to an external location',
          url, where: `${where}:${s.path}`, extra: describeTarget(url),
        });
      }
    }
    if (/package/i.test(s.name)) {
      const inner = cfb.read(s);
      const parsed = parseOle10Native(inner);
      if (parsed) {
        report.add({
          kind: 'embedded',
          title: 'Carries an embedded file',
          detail: `The document has an embedded file${parsed.name ? ` named “${parsed.name}”` : ''}. Embedded programs and scripts are a common delivery trick.`,
          where: `${where}:${s.path}`,
        });
        if (ctx.nested && (isCFB(parsed.data) || parsed.data[0] === 0x50)) ctx.nested(parsed.data, { name: parsed.name, where: `${where}:${s.path}` });
      }
    }
  }

  // Any plain-text remote targets elsewhere in the streams (e.g. INCLUDE/links).
  const whole = latin1.decode(cfb.read(cfb.streams[0] || { start: 0, size: 0 }) || new Uint8Array(0));
  void whole;
}

function hasXlmMacroSheet(data) {
  // BIFF BOUNDSHEET record = 0x0085; byte at +5 of the record body is the sheet type.
  for (let i = 0; i + 8 < data.length; i++) {
    if (data[i] === 0x85 && data[i + 1] === 0x00) {
      const len = data[i + 2] | (data[i + 3] << 8);
      if (len >= 6 && len < 256) {
        const sheetType = data[i + 4 + 5];
        if (sheetType === 1 || sheetType === 2) return true;
      }
    }
  }
  return false;
}

function parseOle10Native(data) {
  if (data.length < 8) return null;
  try {
    const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
    let p = 4; // total size prefix
    if (dv.getUint16(p, true) !== 2) { /* flags */ }
    p += 2;
    const readZ = () => { const s = p; while (p < data.length && data[p] !== 0) p++; const v = latin1.decode(data.subarray(s, p)); p++; return v; };
    const name = readZ();
    readZ(); // source path
    p += 8; // unknown + flags
    const tempPath = readZ(); void tempPath;
    if (p + 4 > data.length) return { name, data: new Uint8Array(0) };
    const dataLen = dv.getUint32(p, true); p += 4;
    const payload = data.subarray(p, Math.min(data.length, p + dataLen));
    return { name, data: payload };
  } catch {
    return null;
  }
}

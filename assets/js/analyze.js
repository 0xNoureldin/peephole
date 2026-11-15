// Entry point: identify the file by its content (not its name) and run the matching analyzer.

import { Report } from './report.js';
import { isZip } from './archive.js';
import { isCFB } from './cfb.js';
import { latin1, startsWith } from './util.js';
import { analyzeZipPackage } from './analyzers/ooxml.js';
import { analyzeCompound } from './analyzers/ole.js';
import { analyzeRtf } from './analyzers/rtf.js';
import { analyzePdf } from './analyzers/pdf.js';
import { analyzeMarkup, looksLikeOfficeMarkup } from './analyzers/markup.js';

const EXT_FAMILY = {
  zip: /\.(docx|docm|dotx|dotm|xlsx|xlsm|xltx|xltm|xlam|pptx|pptm|potx|potm|ppsx|ppsm|ppam|odt|ods|odp|ott|vsdx|vsdm)$/i,
  cfb: /\.(doc|dot|xls|xlt|xla|ppt|pot|pps|msg|vsd)$/i,
  rtf: /\.(rtf|doc)$/i,
  pdf: /\.pdf$/i,
  markup: /\.(xml|mht|mhtml|htm|html|doc|xls)$/i,
};

export function sniff(bytes) {
  if (isZip(bytes)) return 'zip';
  if (isCFB(bytes)) return 'cfb';
  const head = latin1.decode(bytes.subarray(0, 1024));
  if (/^\s*\{\\rt/.test(head)) return 'rtf';
  if (head.includes('%PDF-')) return 'pdf';
  if (startsWith(bytes, [0xef, 0xbb, 0xbf]) || /^\s*</.test(head) || /MIME-Version/i.test(head)) return 'markup';
  return 'unknown';
}

/**
 * Analyze bytes, adding findings to `report`. `where` prefixes locations for nested
 * files (an embedded object inside a document is analyzed with depth + 1).
 */
export async function analyzeBytes(bytes, report, { name = '', where = '', depth = 0 } = {}) {
  const kind = sniff(bytes);
  const ctx = { report, where, depth, name, nested: (b, opts) => (depth < 3 ? analyzeBytes(b, report, { ...opts, depth: depth + 1 }) : null) };

  if (depth === 0 && name) {
    const family = Object.entries(EXT_FAMILY).find(([, re]) => re.test(name));
    if (family && kind !== 'unknown' && !EXT_FAMILY[kind]?.test(name)) {
      report.add({
        level: 'warn', kind: 'note',
        title: 'The file type doesn’t match its name',
        detail: `The name ends in ${name.slice(name.lastIndexOf('.'))}, but the content is ${labelFor(kind)}. Attackers rename files so they open in a different program than you expect.`,
      });
    }
  }

  switch (kind) {
    case 'zip': return analyzeZipPackage(bytes, ctx);
    case 'cfb': return analyzeCompound(bytes, ctx);
    case 'rtf': return analyzeRtf(bytes, ctx);
    case 'pdf': return analyzePdf(bytes, ctx);
    case 'markup':
      if (looksLikeOfficeMarkup(bytes) || depth > 0) return analyzeMarkup(bytes, ctx);
      break;
    default: break;
  }
  if (depth === 0) {
    report.format = 'Unsupported file';
    report.cannotVerify('Peephole checks Word, Excel, PowerPoint, OpenDocument, RTF and PDF files. This file is a different type, so nothing inside it was checked.');
  }
  return null;
}

function labelFor(kind) {
  return { zip: 'a ZIP-based Office file', cfb: 'a legacy Office (OLE) file', rtf: 'an RTF document', pdf: 'a PDF', markup: 'XML or web-page markup' }[kind] || 'something else';
}

export async function analyzeFile(name, bytes) {
  const report = new Report(name, bytes.length);
  try {
    await analyzeBytes(bytes, report, { name });
  } catch (err) {
    report.cannotVerify(`Peephole couldn’t finish reading this file (${err?.message || 'unknown error'}). It may be damaged, or built to confuse scanners.`);
  }
  return report;
}

export async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

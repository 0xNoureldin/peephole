// XML-based and MHTML Office files: Word 2003 XML, SpreadsheetML, Flat OpenDocument,
// and single-file web pages (.mht) that Word/Excel can open. These carry macros as
// text and were the vehicle for CVE-2021-40444 (MHTML).

import { latin1, utf8, decodeXmlEntities, findUrls, describeTarget } from '../util.js';

export function looksLikeOfficeMarkup(bytes) {
  const head = latin1.decode(bytes.subarray(0, 4096));
  return /mso-application|progid=["']?(Word|Excel|PowerPoint)/i.test(head)
    || /<\?mso-application/i.test(head)
    || /office:document|<Workbook\b|<w:wordDocument/i.test(head)
    || /Content-Type:\s*multipart\/related/i.test(head) && /mso|office/i.test(head);
}

export function analyzeMarkup(bytes, ctx) {
  const { report } = ctx;
  const text = decodeText(bytes);
  if (ctx.depth === 0) {
    report.format = /multipart\/related/i.test(text.slice(0, 2000)) ? 'MHTML web archive' : 'XML-based Office file';
  }
  report.part(ctx.where || report.fileName);

  // mso-application progid tells the real target app for a renamed .xml.
  const progid = text.match(/progid=["']?(Word|Excel|PowerPoint)\.\w+/i)?.[1];
  if (progid && ctx.depth === 0 && !/\.(xml|mht|mhtml)$/i.test(report.fileName)) {
    report.add({
      level: 'warn', kind: 'note', title: 'Opens in Office despite its name',
      detail: `This is XML that tells Windows to open it in ${progid}. Renamed XML documents are used to slip past filters.`,
    });
  }

  // VBA stored as a <macrosPresent> / x:MacrosPresent flag, or inline Basic.
  if (/MacrosPresent\s*=\s*["']?yes/i.test(text) || /<w:binData|<x:Macro/i.test(text)) {
    report.add({
      kind: 'macro', title: 'Declares embedded macros',
      detail: 'This XML-based Office file marks itself as containing macros. The macro bytes are stored in the markup and run once enabled.',
      where: ctx.where || report.fileName,
    });
  }

  // MHTML part boundaries referencing script: or the mhtml: scheme (CVE-2021-40444).
  if (/mhtml:|Content-Location:\s*\S+!/i.test(text) && /\.(wsf|hta|js|vbs)\b|script:/i.test(text)) {
    report.add({
      kind: 'exploit', title: 'MHTML archive points at a script resource',
      detail: 'The archive references a script through an mhtml: location, the pattern used by CVE-2021-40444 to load attacker code.',
      where: ctx.where || report.fileName,
    });
  }

  // Inline <script> in an HTML/MHT file opened by Office.
  for (const m of text.matchAll(/<script\b[^>]*>([\s\S]{0,8000}?)<\/script>/gi)) {
    const code = m[1].trim();
    if (code.length > 10) {
      report.add({
        level: 'warn', kind: 'script', title: 'Contains an inline script',
        detail: 'The page embeds script that runs when the page is opened in a browser or in Office’s web-page mode.',
        where: ctx.where || report.fileName,
        modules: [{ name: 'Inline script', kind: 'script', code: code.slice(0, 8000) }],
      });
      break;
    }
  }

  // DDE in SpreadsheetML / Word XML.
  if (/=\s*cmd\s*\||DDEAUTO|=MSEXCEL\|/i.test(text)) {
    report.add({
      kind: 'script', title: 'Contains a DDE / command formula',
      detail: 'A formula or field here tries to launch an external command through DDE.',
      where: ctx.where || report.fileName,
    });
  }

  for (const url of findUrls(text)) {
    const auto = new RegExp(`(src|background|href)\\s*=\\s*["']?${escapeRe(url)}`, 'i').test(text) && /\.(png|jpg|jpeg|gif|bmp|css|js)(\?|$)/i.test(url);
    report.add({
      level: auto ? 'danger' : 'info',
      kind: auto ? 'remote' : 'link',
      title: auto ? 'Loads a remote resource when opened' : 'Contains a link',
      detail: auto
        ? 'The markup pulls this resource in automatically when the file is opened, which reveals that it was opened and the reader’s IP address.'
        : 'An ordinary link. It only opens if you click it.',
      url, where: ctx.where || report.fileName, extra: describeTarget(url),
    });
  }
}

function decodeText(bytes) {
  if (bytes[0] === 0xff && bytes[1] === 0xfe) return new TextDecoder('utf-16le').decode(bytes);
  if (bytes[0] === 0xfe && bytes[1] === 0xff) return new TextDecoder('utf-16be').decode(bytes);
  return utf8.decode(bytes);
}

function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

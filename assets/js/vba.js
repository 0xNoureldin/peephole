// Extracts VBA macro source code from a VBA project inside a compound file,
// following the MS-OVBA specification (compressed container + "dir" stream).

import { decodeCodepage } from './util.js';

/** MS-OVBA 2.4.1 decompression. */
export function decompressVBA(buf, start = 0) {
  if (buf[start] !== 0x01) throw new Error('Not a compressed VBA container');
  const out = [];
  let pos = start + 1;
  while (pos + 2 <= buf.length) {
    const header = buf[pos] | (buf[pos + 1] << 8);
    const chunkStart = pos;
    pos += 2;
    const chunkEnd = Math.min(buf.length, chunkStart + (header & 0x0fff) + 3);
    const decompressedStart = out.length;
    if (!((header >> 15) & 1)) {
      // Uncompressed chunk: 4096 raw bytes.
      const end = Math.min(buf.length, pos + 4096);
      for (; pos < end; pos++) out.push(buf[pos]);
      continue;
    }
    while (pos < chunkEnd) {
      const flags = buf[pos++];
      for (let bit = 0; bit < 8 && pos < chunkEnd; bit++) {
        if (((flags >> bit) & 1) === 0) {
          out.push(buf[pos++]);
        } else {
          if (pos + 2 > chunkEnd) { pos = chunkEnd; break; }
          const token = buf[pos] | (buf[pos + 1] << 8);
          pos += 2;
          const difference = out.length - decompressedStart;
          let bitCount = 4;
          while ((1 << bitCount) < difference) bitCount++;
          const lengthMask = 0xffff >> bitCount;
          const length = (token & lengthMask) + 3;
          const offset = (token >> (16 - bitCount)) + 1;
          const from = out.length - offset;
          if (from < 0) { pos = chunkEnd; break; }
          for (let i = 0; i < length; i++) out.push(out[from + i]);
        }
      }
    }
  }
  return Uint8Array.from(out);
}

/** Parse the decompressed "dir" stream for module names, stream names and offsets. */
function parseDir(dir) {
  const dv = new DataView(dir.buffer, dir.byteOffset, dir.byteLength);
  let codepage = 1252;
  const modules = [];
  let current = null;
  let pos = 0;
  while (pos + 6 <= dir.length) {
    const id = dv.getUint16(pos, true);
    const size = dv.getUint32(pos + 2, true);
    pos += 6;
    if (id === 0x0009) { pos += 6; continue; } // PROJECTVERSION: size field is fixed, data is 6 bytes
    if (pos + size > dir.length) break;
    const data = dir.subarray(pos, pos + size);
    switch (id) {
      case 0x0003: codepage = dv.getUint16(pos, true); break;
      case 0x0019: current = { name: decodeCodepage(data, codepage), stream: null, offset: 0 }; modules.push(current); break;
      case 0x0047: if (current) current.name = new TextDecoder('utf-16le').decode(data) || current.name; break;
      case 0x001a: if (current) current.stream = decodeCodepage(data, codepage); break;
      case 0x0032: if (current) current.streamUnicode = new TextDecoder('utf-16le').decode(data); break;
      case 0x0031: if (current) current.offset = dv.getUint32(pos, true); break;
      case 0x0021: if (current) current.kind = 'module'; break;
      case 0x0022: if (current) current.kind = 'class'; break;
      default: break;
    }
    pos += size;
  }
  return { codepage, modules };
}

/** Returns [{ name, code, project }] for every VBA project in the compound file. */
export function extractVBA(cfb) {
  const results = [];
  const dirStreams = cfb.streams.filter((s) => s.name.toLowerCase() === 'dir' && /(^|\/)vba$/i.test(s.path.slice(0, -4)));
  for (const dirStream of dirStreams) {
    const base = dirStream.path.slice(0, -4); // strip "/dir"
    let parsed;
    try {
      parsed = parseDir(decompressVBA(cfb.read(dirStream)));
    } catch {
      continue;
    }
    for (const m of parsed.modules) {
      const streamName = m.streamUnicode || m.stream || m.name;
      const stream = cfb.findStream(`${base}/${streamName}`);
      if (!stream) continue;
      try {
        const raw = cfb.read(stream);
        const code = decodeCodepage(decompressVBA(raw, m.offset), parsed.codepage).replace(/\r\n?/g, '\n');
        results.push({ name: m.name, kind: m.kind || 'module', code, project: base });
      } catch {
        results.push({ name: m.name, kind: m.kind || 'module', code: '', project: base, unreadable: true });
      }
    }
  }
  return results;
}

export function hasVBAProject(cfb) {
  return cfb.streams.some((s) => s.name.toLowerCase() === 'dir' && /(^|\/)vba$/i.test(s.path.slice(0, -4)))
    || cfb.storages.some((s) => /(^|\/)(_VBA_PROJECT_CUR|Macros|VBA)$/i.test(s.path));
}

// Keyword groups, in the spirit of olevba's triage table.
const RULES = [
  { group: 'Runs automatically', re: /\b(Auto_?Open|AutoExec|Auto_?Close|AutoNew|Document_(Open|Close|New|BeforeClose|ContentControlOnEnter)|Workbook_(Open|Activate|BeforeClose|Deactivate)|Presentation_Open|DocumentBeforeClose|\w+_(Layout|Painted|GotFocus|Resize|Initialize))\b/gi },
  { group: 'Starts programs', re: /\b(Shell(Execute)?|WScript\.Shell|Shell\.Application|Wscript|CreateProcess|Exec|MacScript|AppleScriptTask)\b|\b(powershell|cmd\.exe|mshta|rundll32|regsvr32|certutil|bitsadmin|wmic|schtasks)\b/gi },
  { group: 'Downloads or connects', re: /\b(URLDownloadToFile\w*|XMLHTTP|ServerXMLHTTP|WinHttp(Request)?|InternetOpen\w*|InternetReadFile|Net\.WebClient|DownloadFile|DownloadString|Invoke-WebRequest|Inet\w*)\b/gi },
  { group: 'Writes files', re: /\b(ADODB\.Stream|SaveToFile|CreateTextFile|Scripting\.FileSystemObject|Kill|FileCopy|Put\s+#|Open\s+[^\n]{0,80}\s+For\s+(Output|Binary|Append))\b/gi },
  { group: 'Calls Windows directly', re: /\b(Declare\s+(PtrSafe\s+)?(Function|Sub)|VirtualAlloc\w*|RtlMoveMemory|CreateThread|WriteProcessMemory|CallWindowProc|EnumSystem\w+)\b/gi },
  { group: 'Hides what it does', re: /\b(Chr[BW]?\$?\s*\(|StrReverse|Base64|FromBase64String|ExecuteExcel4Macro|CallByName|Environ\$?\s*\()/gi },
  { group: 'Uses objects', re: /\b(CreateObject|GetObject)\b/gi },
];

export function triageCode(code) {
  const hits = [];
  for (const rule of RULES) {
    const words = new Set();
    for (const m of code.matchAll(rule.re)) words.add(m[0].replace(/\s+/g, ' ').replace(/\($/, '').trim());
    if (words.size) hits.push({ group: rule.group, words: [...words].slice(0, 8) });
  }
  return hits;
}

/** Strips attribute lines so an empty module isn't mistaken for code. */
export function meaningfulCode(code) {
  return code.split('\n').filter((l) => l.trim() && !/^\s*Attribute\s+VB_/i.test(l)).join('\n').trim();
}

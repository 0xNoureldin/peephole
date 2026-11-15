// Reader for OLE Compound File Binary (the container behind .doc, .xls, .ppt,
// vbaProject.bin and embedded objects). Read-only, with loop and bounds guards.

import { utf16 } from './util.js';

const END = 0xfffffffa; // values >= this are special markers (ENDOFCHAIN, FREESECT, ...)

export function isCFB(b) {
  const sig = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
  return b.length >= 512 && sig.every((v, i) => b[i] === v);
}

export function readCFB(buf) {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const u32 = (o) => (o + 4 <= buf.length ? dv.getUint32(o, true) : 0xffffffff);

  const sectorSize = 1 << dv.getUint16(30, true);
  const miniSize = 1 << dv.getUint16(32, true);
  if (sectorSize !== 512 && sectorSize !== 4096) throw new Error('Unsupported compound file sector size');
  const numFat = u32(44);
  const dirStart = u32(48);
  const miniCutoff = u32(56);
  const miniFatStart = u32(60);
  const difatStart = u32(68);
  const numDifat = u32(72);
  const perSector = sectorSize / 4;
  const offsetOf = (s) => (s + 1) * sectorSize;

  // Locate FAT sectors via the header DIFAT and any DIFAT chain.
  const fatSectors = [];
  for (let i = 0; i < 109 && fatSectors.length < numFat; i++) {
    const s = u32(76 + i * 4);
    if (s < END) fatSectors.push(s);
  }
  let d = difatStart;
  for (let guard = 0; d < END && fatSectors.length < numFat && guard <= numDifat; guard++) {
    const off = offsetOf(d);
    for (let i = 0; i < perSector - 1 && fatSectors.length < numFat; i++) {
      const s = u32(off + i * 4);
      if (s < END) fatSectors.push(s);
    }
    d = u32(off + (perSector - 1) * 4);
  }

  const fat = new Uint32Array(fatSectors.length * perSector);
  fatSectors.forEach((s, i) => {
    const off = offsetOf(s);
    for (let j = 0; j < perSector; j++) fat[i * perSector + j] = u32(off + j * 4);
  });

  const readChain = (start, size) => {
    const sectors = [];
    const seen = new Set();
    for (let s = start; s < END && s < fat.length && !seen.has(s); s = fat[s]) {
      seen.add(s);
      sectors.push(s);
    }
    const length = Math.min(size ?? sectors.length * sectorSize, sectors.length * sectorSize);
    const out = new Uint8Array(length);
    let w = 0;
    for (const s of sectors) {
      if (w >= length) break;
      const off = offsetOf(s);
      const piece = buf.subarray(off, Math.min(off + Math.min(sectorSize, length - w), buf.length));
      out.set(piece, w);
      w += Math.min(sectorSize, length - w);
    }
    return out;
  };

  // Directory entries (128 bytes each).
  const dir = readChain(dirStart);
  const entries = [];
  for (let o = 0; o + 128 <= dir.length; o += 128) {
    const e = new DataView(dir.buffer, dir.byteOffset + o, 128);
    const nameLen = Math.min(e.getUint16(64, true), 64);
    entries.push({
      id: entries.length,
      name: nameLen >= 2 ? utf16.decode(dir.subarray(o, o + nameLen - 2)) : '',
      type: dir[o + 66], // 1 storage, 2 stream, 5 root
      left: e.getUint32(68, true),
      right: e.getUint32(72, true),
      child: e.getUint32(76, true),
      start: e.getUint32(116, true),
      size: Math.min(e.getUint32(120, true), buf.length * 4),
      path: '',
    });
  }
  const root = entries[0];
  if (!root || root.type !== 5) throw new Error('This compound file has no root entry');

  const miniStream = readChain(root.start, root.size);
  const miniFatBytes = miniFatStart < END ? readChain(miniFatStart) : new Uint8Array(0);
  const miniFat = new Uint32Array(miniFatBytes.buffer.slice(miniFatBytes.byteOffset, miniFatBytes.byteOffset + (miniFatBytes.length & ~3)));

  const readMini = (start, size) => {
    const out = new Uint8Array(size);
    const seen = new Set();
    let w = 0;
    for (let s = start; s < END && s < miniFat.length && !seen.has(s) && w < size; s = miniFat[s]) {
      seen.add(s);
      const n = Math.min(miniSize, size - w);
      out.set(miniStream.subarray(s * miniSize, s * miniSize + n), w);
      w += n;
    }
    return out;
  };

  // Walk the red-black tree to give every entry a full path like "Macros/VBA/dir".
  const visited = new Set();
  const visit = (id, parent) => {
    if (id >= entries.length || visited.has(id)) return;
    visited.add(id);
    const e = entries[id];
    visit(e.left, parent);
    e.path = parent ? `${parent}/${e.name}` : e.name;
    visit(e.right, parent);
    if (e.type === 1) visit(e.child, e.path);
  };
  visit(root.child, '');

  const streams = entries.filter((e) => e.type === 2 && e.path);
  const storages = entries.filter((e) => e.type === 1 && e.path);

  const read = (e) => (e.size < miniCutoff ? readMini(e.start, e.size) : readChain(e.start, e.size));
  const findStream = (path) => streams.find((s) => s.path.toLowerCase() === path.toLowerCase());

  return { streams, storages, read, findStream };
}

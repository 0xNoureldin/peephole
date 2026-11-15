// Thin wrapper around JSZip (vendored in assets/vendor). In the browser JSZip is a
// global loaded by index.html; in Node tests it is injected with setZipLibrary().

let ZipLib = typeof globalThis !== 'undefined' ? globalThis.JSZip : undefined;

export function setZipLibrary(lib) { ZipLib = lib; }

export function isZip(b) {
  return b.length > 4 && b[0] === 0x50 && b[1] === 0x4b && b[2] === 0x03 && b[3] === 0x04;
}

const MAX_ENTRY = 96 * 1024 * 1024;

export async function openZip(bytes) {
  if (!ZipLib) throw new Error('ZIP support failed to load. Refresh the page and try again.');
  const zip = await ZipLib.loadAsync(bytes, { checkCRC32: false });
  const names = Object.keys(zip.files).filter((n) => !zip.files[n].dir);
  const sizeOf = (name) => zip.files[name]?._data?.uncompressedSize ?? 0;
  return {
    names,
    has: (name) => !!zip.files[name],
    find: (re) => names.filter((n) => re.test(n)),
    async bytes(name) {
      const f = zip.files[name];
      if (!f) return null;
      if (sizeOf(name) > MAX_ENTRY) throw new Error(`${name} is too large to inspect safely`);
      return f.async('uint8array');
    },
    async text(name) {
      const f = zip.files[name];
      if (!f) return null;
      if (sizeOf(name) > MAX_ENTRY) throw new Error(`${name} is too large to inspect safely`);
      return f.async('string');
    },
  };
}

// Store-only archive builder, used only to create the built-in demo files.
export async function buildZip(files) {
  const zip = new ZipLib();
  for (const [name, content] of Object.entries(files)) zip.file(name, content);
  return zip.generateAsync({ type: 'uint8array', compression: 'DEFLATE' });
}

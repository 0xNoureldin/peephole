// PDF documents. Flags JavaScript, auto-run actions, launch/URI actions,
// embedded files and remote-form submission.

import { latin1, inflate, findUrls, describeTarget, indexOfBytes, concatBytes } from '../util.js';

export async function analyzePdf(bytes, ctx) {
  const { report } = ctx;
  if (ctx.depth === 0) report.format = 'PDF document';
  report.part(ctx.where || report.fileName);

  // Work on the raw text plus the inflated content of every FlateDecode stream,
  // so actions hidden inside compressed object streams are still seen.
  const raw = latin1.decode(bytes);
  const inflated = await inflateStreams(bytes);
  const hay = raw + '\n' + inflated;

  const hasJS = /\/JS\b|\/JavaScript\b/.test(hay);
  const autoAction = /\/OpenAction\b/.test(hay) || /\/AA\b/.test(hay);

  if (hasJS) {
    const snippets = extractJsSnippets(hay);
    report.add({
      kind: 'script',
      title: autoAction ? 'Runs JavaScript automatically when opened' : 'Contains JavaScript',
      detail: autoAction
        ? 'The PDF defines JavaScript and an automatic action (OpenAction / additional actions). Readers that allow PDF JavaScript can run this code as soon as the file opens.'
        : 'The PDF contains JavaScript. PDF JavaScript can show dialogs, reach the network in some readers, and has been used to trigger reader vulnerabilities.',
      where: ctx.where || report.fileName,
      modules: snippets.length ? [{ name: 'PDF JavaScript', kind: 'script', code: snippets.join('\n\n/* --- next script --- */\n\n') }] : undefined,
    });
  }

  for (const m of hay.matchAll(/\/Launch\b/g)) {
    void m;
    report.add({
      kind: 'exploit',
      title: 'Uses a Launch action to start a program',
      detail: 'A /Launch action tries to run an external program or command. Legitimate PDFs almost never do this.',
      where: ctx.where || report.fileName,
    });
    break;
  }

  // /URI actions and /SubmitForm targets are remote; GoToR / embedded go-to remote.
  const uriTargets = new Set();
  for (const m of hay.matchAll(/\/(URI|F|FS)\s*\(((?:[^()\\]|\\.)*)\)/g)) {
    const val = m[2].replace(/\\([()\\])/g, '$1');
    if (/^(https?|ftp|file|mailto|javascript):/i.test(val) || /^\\\\/.test(val)) uriTargets.add(val);
  }
  findUrls(hay).forEach((u) => uriTargets.add(u));

  const submits = /\/SubmitForm\b/.test(hay);
  if (submits) {
    report.add({
      kind: 'remote',
      title: 'Can submit form data to a remote server',
      detail: 'The PDF defines a form submission action, which sends entered data to a URL. Combined with auto-run JavaScript this can happen without a visible button.',
      where: ctx.where || report.fileName,
    });
  }

  const autoFetch = submits || (autoAction && [...uriTargets].some((u) => /^(https?|ftp|file):/i.test(u) || /^\\\\/.test(u)));
  for (const url of uriTargets) {
    if (/^(mailto|javascript):/i.test(url)) continue;
    report.add({
      level: autoFetch ? 'danger' : 'info',
      kind: autoFetch ? 'remote' : 'link',
      title: autoFetch ? 'Contacts a remote address' : 'Contains a link',
      detail: autoFetch
        ? 'The PDF references this address and has an automatic action, so it may be contacted without you clicking anything.'
        : 'An ordinary link. It only opens if you click it.',
      url, where: ctx.where || report.fileName, extra: describeTarget(url),
    });
  }

  if (/\/EmbeddedFile\b|\/EmbeddedFiles\b/.test(hay)) {
    report.add({
      level: 'warn', kind: 'embedded',
      title: 'Contains an embedded file',
      detail: 'The PDF carries another file inside it. Check what it is before opening — embedded executables and scripts are a known delivery method.',
      where: ctx.where || report.fileName,
    });
  }
}

async function inflateStreams(bytes) {
  const pieces = [];
  let total = 0;
  const marker = Uint8Array.from('stream', (c) => c.charCodeAt(0));
  let idx = indexOfBytes(bytes, marker, 0);
  let guard = 0;
  while (idx >= 0 && guard++ < 4000 && total < 48 * 1024 * 1024) {
    let s = idx + marker.length;
    if (bytes[s] === 0x0d) s++;
    if (bytes[s] === 0x0a) s++;
    const end = indexOfBytes(bytes, Uint8Array.from('endstream', (c) => c.charCodeAt(0)), s);
    if (end < 0) break;
    const chunk = bytes.subarray(s, end);
    if (chunk[0] === 0x78) { // zlib header
      try {
        const out = await inflate(chunk, 'deflate', { partial: true, limit: 24 * 1024 * 1024 });
        pieces.push(out); total += out.length;
      } catch { /* skip */ }
    }
    idx = indexOfBytes(bytes, marker, end + 1);
  }
  return latin1.decode(concatBytes(pieces, total));
}

function extractJsSnippets(hay) {
  const out = [];
  for (const m of hay.matchAll(/\/(?:JS|JavaScript)\s*\(((?:[^()\\]|\\.|\((?:[^()\\]|\\.)*\))*)\)/g)) {
    const code = m[1].replace(/\\([()\\nrt])/g, (_, c) => ({ n: '\n', r: '\r', t: '\t' }[c] || c));
    if (code.trim().length > 4) out.push(code.trim());
  }
  for (const m of hay.matchAll(/\/(?:JS|JavaScript)\s*(\d+)\s+0\s+R/g)) void m;
  return [...new Set(out)].slice(0, 20);
}

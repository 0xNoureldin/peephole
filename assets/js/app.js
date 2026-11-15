import { analyzeFile, sha256Hex } from './analyze.js';
import { formatBytes } from './util.js';
import { SAMPLES, makeSample } from './samples.js';

const $ = (sel, root = document) => root.querySelector(sel);
const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; };

const MAX_SIZE = 80 * 1024 * 1024;
const KIND_META = {
  macro:    { icon: 'M', label: 'Macro code' },
  script:   { icon: 'S', label: 'Script' },
  remote:   { icon: 'R', label: 'Remote request' },
  exploit:  { icon: 'X', label: 'Exploit pattern' },
  embedded: { icon: 'E', label: 'Embedded file' },
  link:     { icon: 'L', label: 'Link' },
  note:     { icon: 'i', label: 'Note' },
};

// ---------- counters: total checked, safe, dangerous ----------
// Prefers the global totals from /api/count; if that endpoint isn't configured
// yet (or we're on a plain static server), falls back to a private per-device
// tally in localStorage. The file itself is never sent either way.
const COUNT_API = '/api/count';
let globalCount = false;
const LK = { total: 'peephole.checks', safe: 'peephole.safe', dangerous: 'peephole.dangerous' };

function lget(k) { try { return parseInt(localStorage.getItem(k) || '0', 10) || 0; } catch { return 0; } }
function lset(k, v) { try { localStorage.setItem(k, String(v)); } catch {} }
function localTotals() { return { total: lget(LK.total), safe: lget(LK.safe), dangerous: lget(LK.dangerous) }; }
function localInc(verdict) {
  const total = lget(LK.total) + 1; lset(LK.total, total);
  let safe = lget(LK.safe), dangerous = lget(LK.dangerous);
  if (verdict === 'safe') { safe += 1; lset(LK.safe, safe); }
  else if (verdict === 'dangerous') { dangerous += 1; lset(LK.dangerous, dangerous); }
  return { total, safe, dangerous };
}

function showCounts(d) {
  $('#stat-total').textContent = Number(d.total || 0).toLocaleString();
  $('#stat-safe').textContent = Number(d.safe || 0).toLocaleString();
  $('#stat-dangerous').textContent = Number(d.dangerous || 0).toLocaleString();
  $('#count-row').hidden = false;
}

async function loadCount() {
  try {
    const r = await fetch(COUNT_API, { method: 'GET' });
    if (r.ok) {
      const d = await r.json();
      if (d && d.configured) { globalCount = true; showCounts(d); return; }
    }
  } catch {}
  globalCount = false;
  const t = localTotals();
  if (t.total > 0) showCounts(t);
}

async function bumpCount(verdict) {
  if (globalCount) {
    try {
      const r = await fetch(`${COUNT_API}?v=${encodeURIComponent(verdict || '')}`, { method: 'POST' });
      if (r.ok) { const d = await r.json(); if (d && typeof d.total === 'number') { showCounts(d); return; } }
    } catch {}
  }
  showCounts(localInc(verdict));
}

// ---------- theme ----------
function initTheme() {
  const saved = (() => { try { return localStorage.getItem('peephole.theme'); } catch { return null; } })();
  if (saved) document.documentElement.setAttribute('data-theme', saved);
  $('#theme').addEventListener('click', () => {
    const dark = !(document.documentElement.getAttribute('data-theme') === 'dark'
      || (!document.documentElement.getAttribute('data-theme') && matchMedia('(prefers-color-scheme: dark)').matches));
    const next = dark ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', next);
    try { localStorage.setItem('peephole.theme', next); } catch {}
  });
}

// ---------- scanning ----------
let busy = false;

async function scan(name, bytes, opts = {}) {
  if (busy) return;
  busy = true;
  showStage('working', name);
  try {
    // Yield so the working state paints before the (synchronous-ish) analysis.
    await new Promise((r) => setTimeout(r, 30));
    const [report, hash] = await Promise.all([analyzeFile(name, bytes), sha256Hex(bytes).catch(() => null)]);
    renderReport(report, hash);
    // Demo files (opts.count === false) don't count toward the totals.
    if (opts.count !== false) await bumpCount(report.verdict);
  } catch (err) {
    renderError(err?.message || 'Something went wrong while reading the file.');
  } finally {
    busy = false;
  }
}

function handleFiles(list) {
  const file = list && list[0];
  if (!file) return;
  if (file.size > MAX_SIZE) { renderError(`That file is ${formatBytes(file.size)}. Peephole handles files up to ${formatBytes(MAX_SIZE)}.`); return; }
  const reader = new FileReader();
  reader.onload = () => scan(file.name, new Uint8Array(reader.result));
  reader.onerror = () => renderError('The file could not be read from your device.');
  reader.readAsArrayBuffer(file);
}

// ---------- rendering ----------
function showStage(stage, name) {
  $('#result').hidden = stage !== 'result';
  $('#working').hidden = stage !== 'working';
  if (stage === 'working') $('#working-name').textContent = name;
}

function renderError(message) {
  const r = $('#result');
  r.className = 'result verdict-unknown';
  r.innerHTML = '';
  const head = el('div', 'verdict-head');
  head.append(el('div', 'verdict-badge', 'Couldn’t check'));
  head.append(el('p', 'verdict-line', message));
  r.append(head);
  showStage('result');
  r.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function renderReport(report, hash) {
  const v = report.verdict;
  const r = $('#result');
  r.className = `result verdict-${v}`;
  r.innerHTML = '';

  const dangers = report.findings.filter((f) => f.level === 'danger');
  const warns = report.findings.filter((f) => f.level === 'warn');
  const infos = report.findings.filter((f) => f.level === 'info');

  // Verdict header
  const head = el('div', 'verdict-head');
  const badge = el('div', 'verdict-badge');
  badge.append(el('span', 'verdict-dot'));
  badge.append(el('span', null, v === 'dangerous' ? 'Dangerous' : v === 'safe' ? 'Looks safe' : 'Can’t be sure'));
  head.append(badge);

  const line = el('p', 'verdict-line');
  if (v === 'dangerous') line.textContent = dangerSummary(dangers);
  else if (v === 'safe') line.textContent = 'No macros, embedded scripts or automatic internet requests were found. Ordinary links, if any, are listed below and only open when you click them.';
  else line.textContent = report.unverifiable || 'This file couldn’t be fully inspected.';
  head.append(line);
  r.append(head);

  // File facts
  const facts = el('div', 'facts');
  facts.append(fact('File', report.fileName));
  facts.append(fact('Type', report.format));
  facts.append(fact('Size', formatBytes(report.size)));
  if (hash) facts.append(fact('SHA-256', hash, true));
  r.append(facts);

  // Findings
  if (dangers.length) r.append(findingGroup('What makes it dangerous', dangers));
  if (warns.length) r.append(findingGroup('Worth a closer look', warns));
  if (infos.length) r.append(findingGroup('For your information', infos, true));

  if (report.unverifiable && v !== 'unknown') {
    const note = el('div', 'softnote');
    note.textContent = report.unverifiable;
    r.append(note);
  }

  // Reset action
  const again = el('button', 'btn-ghost', 'Check another file');
  again.addEventListener('click', () => { showStage(null); $('#drop').scrollIntoView({ behavior: 'smooth', block: 'center' }); $('#file').value = ''; });
  r.append(again);

  showStage('result');
  r.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function dangerSummary(dangers) {
  const kinds = new Set(dangers.map((f) => f.kind));
  const bits = [];
  if (kinds.has('macro')) bits.push('runs macro code');
  if (kinds.has('script')) bits.push('contains active scripts');
  if (kinds.has('remote')) bits.push('reaches out to the internet on its own');
  if (kinds.has('exploit')) bits.push('uses a known exploit pattern');
  if (kinds.has('embedded')) bits.push('carries a hidden program');
  const list = bits.length > 1 ? bits.slice(0, -1).join(', ') + ' and ' + bits.slice(-1) : bits[0] || 'behaves in a risky way';
  return `This file ${list}. The exact code and addresses are shown below. Don’t open it in Office unless you fully trust where it came from.`;
}

function fact(label, value, mono) {
  const d = el('div', 'fact');
  d.append(el('span', 'fact-k', label));
  const val = el('span', 'fact-v' + (mono ? ' mono' : ''), value);
  d.append(val);
  return d;
}

function findingGroup(title, findings, muted) {
  const g = el('section', 'fgroup' + (muted ? ' muted' : ''));
  g.append(el('h3', 'fgroup-title', title));
  for (const f of findings) g.append(findingCard(f));
  return g;
}

function findingCard(f) {
  const meta = KIND_META[f.kind] || KIND_META.note;
  const card = el('article', `finding lvl-${f.level}`);

  const top = el('div', 'finding-top');
  const tag = el('span', 'finding-tag');
  tag.append(el('span', 'finding-ic', meta.icon));
  tag.append(el('span', null, meta.label));
  top.append(tag);
  top.append(el('h4', 'finding-title', f.title));
  card.append(top);

  if (f.detail) card.append(el('p', 'finding-detail', f.detail));

  if (f.url) {
    const box = el('div', 'url-box');
    box.append(el('span', 'url-label', f.kind === 'link' ? 'Link' : 'Address it requests'));
    const row = el('div', 'url-row');
    const code = el('code', 'url mono'); code.textContent = f.url;
    row.append(code);
    row.append(copyBtn(f.url));
    box.append(row);
    if (f.extra) box.append(el('p', 'url-extra', f.extra));
    card.append(box);
  }

  if (f.where) card.append(el('p', 'finding-where', `Location: ${f.where}`));

  if (f.behaviors && f.behaviors.length) {
    const b = el('div', 'behaviors');
    for (const group of f.behaviors) {
      const chip = el('div', 'behavior');
      chip.append(el('span', 'behavior-g', group.group));
      const words = el('span', 'behavior-w mono'); words.textContent = group.words.join('  ·  ');
      chip.append(words);
      b.append(chip);
    }
    card.append(b);
  }

  if (f.snippet) card.append(codeBlock('Field code', f.snippet));

  if (f.modules && f.modules.length) {
    for (const m of f.modules) {
      const n = (m.code || '').split('\n').length;
      card.append(codeBlock(`${m.name}${m.kind ? ' · ' + m.kind : ''}`, m.code, `${n} line${n === 1 ? '' : 's'}`));
    }
  }

  return card;
}

function copyBtn(text) {
  const b = el('button', 'copy', 'Copy');
  b.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(text); b.textContent = 'Copied'; }
    catch { const r = document.createRange(); r.selectNodeContents(b.previousElementSibling || b); getSelection().removeAllRanges(); getSelection().addRange(r); b.textContent = 'Selected'; }
    setTimeout(() => (b.textContent = 'Copy'), 1400);
  });
  return b;
}

function codeBlock(label, code, meta) {
  const wrap = el('details', 'code');
  wrap.open = (code || '').length < 1400;
  const sum = el('summary', 'code-sum');
  sum.append(el('span', 'code-label', label));
  if (meta) sum.append(el('span', 'code-meta', meta));
  sum.append(copyInline(code));
  wrap.append(sum);
  const pre = el('pre', 'code-body mono');
  pre.append(el('code', null, code || '(empty)'));
  wrap.append(pre);
  return wrap;
}

function copyInline(text) {
  const b = el('span', 'code-copy', 'Copy');
  b.addEventListener('click', async (e) => {
    e.preventDefault();
    try { await navigator.clipboard.writeText(text); b.textContent = 'Copied'; } catch { b.textContent = 'Press Ctrl+C'; }
    setTimeout(() => (b.textContent = 'Copy'), 1400);
  });
  return b;
}

// ---------- samples ----------
function initSamples() {
  const row = $('#samples');
  for (const s of SAMPLES) {
    const b = el('button', 'sample' + (s.danger ? ' sample-danger' : ' sample-safe'));
    b.append(el('span', 'sample-label', s.label));
    b.append(el('span', 'sample-name mono', s.name));
    b.append(el('span', 'sample-note', s.note));
    b.addEventListener('click', async () => {
      const made = await makeSample(s.id);
      if (made) scan(made.name, made.bytes, { count: false });
    });
    row.append(b);
  }
}

// ---------- wiring ----------
function initDropzone() {
  const drop = $('#drop');
  const input = $('#file');
  drop.addEventListener('click', () => input.click());
  drop.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } });
  input.addEventListener('change', () => handleFiles(input.files));
  ['dragenter', 'dragover'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add('over'); }));
  ['dragleave', 'drop'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); if (ev === 'dragleave' && drop.contains(e.relatedTarget)) return; drop.classList.remove('over'); }));
  drop.addEventListener('drop', (e) => handleFiles(e.dataTransfer.files));
  // Whole-window drag so a near-miss still works.
  window.addEventListener('dragover', (e) => e.preventDefault());
  window.addEventListener('drop', (e) => { e.preventDefault(); if (!drop.contains(e.target)) handleFiles(e.dataTransfer.files); });
}

function boot() {
  initTheme();
  initDropzone();
  initSamples();
  loadCount();
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
else boot();

// The result of one scan. Analyzers add findings; the verdict is derived from them.
//
// level:  'danger' -> makes the file Dangerous (macros, scripts, automatic remote requests)
//         'warn'   -> worth knowing, does not change the verdict on its own
//         'info'   -> context, e.g. ordinary links that only open when clicked
// kind:   'macro' | 'script' | 'remote' | 'exploit' | 'embedded' | 'link' | 'note'

export class Report {
  constructor(fileName, size) {
    this.fileName = fileName;
    this.size = size;
    this.format = 'Unknown';
    this.findings = [];
    this.inspected = new Set();
    this.unverifiable = null; // reason string when the file can't be fully inspected
    this.notes = [];
  }

  add(finding) {
    const key = [finding.kind, finding.title, finding.url || '', finding.where || '', finding.code?.name || ''].join('|');
    if (this.findings.some((f) => f.key === key)) return;
    this.findings.push({ level: 'danger', ...finding, key });
  }

  part(name) { this.inspected.add(name); }

  cannotVerify(reason) { if (!this.unverifiable) this.unverifiable = reason; }

  get verdict() {
    if (this.findings.some((f) => f.level === 'danger')) return 'dangerous';
    if (this.unverifiable) return 'unknown';
    return 'safe';
  }

  get counts() {
    const c = { danger: 0, warn: 0, info: 0 };
    for (const f of this.findings) c[f.level]++;
    return c;
  }
}

# Peephole

**See what a file does before you open it.** Peephole checks a Word, Excel,
PowerPoint, PDF, RTF or XML file for the things that make documents dangerous —
macros, embedded scripts, and code that silently reaches out to the internet —
and shows you the exact macro source, command, or URL it found.

Everything runs **in the browser**. The file is never uploaded; no server ever
sees it. There is no login, no sign-up, and no tracking.

→ Built by [Noureldin Shaban](https://www.linkedin.com/in/noureldin-shaban-20176b240/).

## What it detects

| Category | Examples |
| --- | --- |
| **VBA macros** | Decompresses the `vbaProject.bin` / OLE macro storage and shows the real source, flagging auto-run entry points (`Auto_Open`, `Document_Open`), process launches (`Shell`, `powershell`), downloads (`URLDownloadToFile`, `XMLHTTP`) and more. |
| **Automatic internet requests** | External image relationships (the tracking-beacon / read-receipt pattern), remote templates, linked OLE objects, remote resources in XML/MHT markup, PDF auto-submit. Shows the exact URL or UNC path. |
| **Macro-less execution** | DDE / `DDEAUTO` command fields, Excel 4.0 (XLM) macro sheets, RTF auto-updating linked objects (CVE-2017-0199), Equation Editor objects (CVE-2017-11882), MHTML script references (CVE-2021-40444). |
| **PDF danger** | JavaScript, `OpenAction` auto-run, `/Launch` actions, form submission, embedded files. |
| **Embedded payloads** | Programs/scripts bundled inside a document, and files whose real type doesn't match their name. |

A file is reported **Dangerous** if it contains macros, active scripts, or
automatic remote requests; **Looks safe** if none of those are present (ordinary
click-only links are listed separately); or **Can't be sure** if the type isn't
supported or the file is damaged.

## Supported formats

`.docx .docm .xlsx .xlsm .xlam .pptx .pptm .ppam` and the rest of the OOXML
family · legacy `.doc .xls .ppt .xla` (OLE) · `.rtf` · `.pdf` ·
Word/Excel 2003 `.xml` and `.mht/.mhtml` · OpenDocument `.odt .ods .odp`.

## Run locally

```bash
# any static server works, e.g.
python3 -m http.server 4321
# then open http://127.0.0.1:4321
```

## Tests

```bash
npm test
```

Builds known-dangerous and known-safe samples (plus real Office add-ins when
present) and asserts the verdicts.

## Deploy

Static site — no build step. On **Vercel**, import the repo and deploy; the
included `vercel.json` sets `cleanUrls` and strict security headers
(a locked-down Content-Security-Policy, `nosniff`, `no-referrer`, `DENY` framing).

## How it's built

Plain ES modules, no framework. The only third-party dependency is
[JSZip](https://stuk.github.io/jszip/) (MIT), vendored in `assets/vendor/` so the
page never contacts a CDN. ZIP inflation and SHA-256 use the browser's built-in
`DecompressionStream` and Web Crypto.

```
index.html              # UI (inline CSS, theming)
assets/js/
  analyze.js            # format sniffing + dispatch
  cfb.js  vba.js         # OLE compound-file reader + MS-OVBA macro decompression
  archive.js            # JSZip wrapper
  analyzers/            # ooxml, ole, rtf, pdf, markup
  app.js samples.js     # UI controller + in-browser demo files
tests/run.mjs           # Node test suite
```

## Scope & honesty

Peephole flags behaviours, not every possible threat. “Looks safe” means none of
the checked dangerous behaviours are present in the parts it can read — it is a
strong first look, not a full antivirus or a guarantee. Always consider where a
file came from. The check counter is stored only in your browser and is never
sent anywhere.

## License

MIT.

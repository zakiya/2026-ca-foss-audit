# 2026-ca-foss-audit

Scripts and references to support [2026 CA open source audit](./html/report.html)


## Setup

```bash
uv sync
```

## Usage

input/sites-to-audit.txt 
Put one domain or URL per line in a text file (blank lines and `#` comments are
ignored), then run:

```bash
uv run scripts/audit.py 
```

Flags:
- `--probe`: for sites with no signature match, try a few extra polite
  marker-path requests (see Limitations).
- `--advanced`: also detect common front-end frameworks/libraries/analytics/CDN
  tools (jQuery, React, Google Analytics, Bootstrap, Cloudflare, reCAPTCHA,
  etc.) and add a `frameworks_libraries` column to the console table and CSV.
- `-o`/`--output`: change the CSV output path (default: `output/TECHSTACK.csv`).

## Output

- A console table: `HOSTNAME | PLATFORM | OPEN SOURCE? | EVIDENCE` (a fifth
  `FRAMEWORKS/LIBRARIES` column is added when run with `--advanced`).
- `TECHSTACK.csv` with columns `hostname, http_status, platform, open_source,
  evidence` (plus `frameworks_libraries` when run with `--advanced`).
- A one-line tally, e.g. `7 open source, 2 proprietary, 1 undetermined`.

The `open_source` column is `yes`, `no`, `unknown` (no signature matched), or
`error` (site unreachable). The `http_status` column is `none` when the site
could not be reached.

With `--advanced`, `frameworks_libraries` is a semicolon-separated,
alphabetically sorted list of every detected front-end framework/library/
analytics/CDN tool (e.g. `Bootstrap; Cloudflare; Google Analytics; jQuery`),
or empty if none were detected — unlike `platform`, a site can have any
number of these at once.

## How detection works

`signatures.py` holds the fingerprint definitions. Each signature matches on
response headers, `Set-Cookie` names, the `<meta name="generator">` tag, and
tell-tale asset paths in the HTML. When several platforms match, the
highest-weighted (most specific) one wins. See the comment block at the top of
`signatures.py` for how to add new signatures.

`LIBRARY_SIGNATURES` in the same file uses the identical matcher format to
fingerprint common front-end frameworks, JS libraries, analytics tags, and
CDN/embed tools. Unlike the platform signatures, when `--advanced` is passed
every matching signature is reported, not just the highest-weight one, since
a site can use many at once.

## Limitations

- CDN-fronted or heavily cached sites can hide platform signals → reported as
  `undetermined`. Try `--probe` for a few extra polite checks.
- By default, fingerprints identify only the primary CMS/platform (the
  meaningful open-source question for most audits). Pass `--advanced` to
  also detect common front-end frameworks, JS libraries, analytics, and CDN
  tools — but this is still a curated, local signature list, not exhaustive.
  Heavily bundled/minified JS (e.g. framework code inlined by a build tool
  without a recognizable CDN URL or literal marker string) won't be
  detected, since detection is substring/regex matching against raw headers
  and HTML, not JS execution or bundle inspection. It also inherits the
  existing `MAX_BODY_BYTES` (200 KB) cap on how much of the page body is
  fetched and scanned.

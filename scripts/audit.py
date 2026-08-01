#!/usr/bin/env python3
"""Audit a list of websites and classify each site's CMS/platform as open source
or proprietary, using local fingerprinting of HTTP headers + HTML.
"""

import argparse
import csv
import re
import sys

try:
    import requests
except ImportError:
    sys.exit("Missing dependency 'requests'. Run: pip install -r requirements.txt")

from signatures import SIGNATURES, LIBRARY_SIGNATURES, PROBE_PATHS

USER_AGENT = (
    "web-tech-audit/1.0 (CMS open-source classification; "
    "local fingerprinting; +https://ca.gov)"
)
TIMEOUT = 12
MAX_BODY_BYTES = 200_000

META_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)

INPUT = "input/sites-to-audit.txt"


def load_sites(path):
    """Read the input file into a list of raw site strings (comments/blanks skipped)."""
    sites = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Tolerate CSV-style "domain,count" lines by taking the first field.
            sites.append(line.split(",")[0].strip())
    return sites


def normalize_url(site):
    """Turn a bare domain into an https URL; leave existing schemes alone."""
    if not re.match(r"^https?://", site, re.IGNORECASE):
        return "https://" + site
    return site


def fetch(url):
    """Fetch a URL. Return (response, error). Exactly one is not None."""
    try:
        resp = requests.get(
            url,
            allow_redirects=True,
            timeout=TIMEOUT,
            headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*"},
            stream=True,
        )
        # Read a capped amount of body so huge pages don't blow up memory.
        body = resp.raw.read(MAX_BODY_BYTES, decode_content=True)
        text = body.decode(resp.encoding or "utf-8", errors="replace")
        resp._audit_body = text
        return resp, None
    except requests.exceptions.SSLError as exc:
        return None, f"TLS error: {exc.__class__.__name__}"
    except requests.exceptions.ConnectionError:
        return None, "connection error / DNS failure"
    except requests.exceptions.Timeout:
        return None, f"timeout after {TIMEOUT}s"
    except requests.exceptions.RequestException as exc:
        return None, f"{exc.__class__.__name__}"


def _meta_generators(body):
    return META_GENERATOR_RE.findall(body or "")


def _run_signature_matchers(resp, signature_list):
    """Run a list of signatures against a response. Return a list of (signature, evidence)."""
    headers = resp.headers
    cookies = "; ".join(
        f"{c.name}={c.value}" for c in resp.cookies
    )
    # Also include raw Set-Cookie header value(s) for cookies not parsed into the jar.
    set_cookie = headers.get("Set-Cookie", "")
    cookie_blob = f"{cookies}; {set_cookie}"
    body = getattr(resp, "_audit_body", "") or ""
    generators = _meta_generators(body)

    hits = []
    for sig in signature_list:
        matchers = sig["matchers"]
        evidence = None

        for header_name, pattern in matchers.get("header", []):
            value = headers.get(header_name)
            if value and re.search(pattern, value, re.IGNORECASE):
                evidence = f"header {header_name}: {value[:80]}"
                break

        if not evidence:
            for pattern in matchers.get("meta_generator", []):
                for gen in generators:
                    if re.search(pattern, gen, re.IGNORECASE):
                        evidence = f'meta generator: "{gen[:80]}"'
                        break
                if evidence:
                    break

        if not evidence:
            for pattern in matchers.get("cookie", []):
                if cookie_blob and re.search(pattern, cookie_blob, re.IGNORECASE):
                    evidence = f"cookie match: {pattern}"
                    break

        if not evidence:
            for substr in matchers.get("body_path", []):
                if substr.lower() in body.lower():
                    evidence = f"html contains: {substr}"
                    break

        if evidence:
            hits.append((sig, evidence))

    return hits


def match_signatures(resp):
    """Run CMS/platform signatures against a response. Return list of (signature, evidence)."""
    return _run_signature_matchers(resp, SIGNATURES)


def match_library_signatures(resp):
    """Run framework/library signatures against a response.

    Return list of (signature, evidence) for ALL matches. Unlike
    match_signatures(), no single winner is picked, since a site can
    legitimately use many frameworks/libraries at once.
    """
    return _run_signature_matchers(resp, LIBRARY_SIGNATURES)


def probe(url):
    """Try a few marker paths. Return (signature_name, open_source, evidence) or None."""
    base = url.rstrip("/")
    for path, name, open_source in PROBE_PATHS:
        try:
            resp = requests.get(
                base + path,
                allow_redirects=True,
                timeout=TIMEOUT,
                headers={"User-Agent": USER_AGENT},
            )
        except requests.exceptions.RequestException:
            continue
        if resp.status_code == 200:
            return name, open_source, f"probe {path} -> 200"
    return None


def classify(site, use_probe=False, advanced=False):
    """Audit one site. Return a result dict."""
    url = normalize_url(site)
    result = {
        "hostname": site,
        "http_status": "none",
        "platform": "undetermined",
        "open_source": "unknown",
        "evidence": "",
    }
    if advanced:
        result["frameworks_libraries"] = ""

    resp, error = fetch(url)
    if error:
        result["evidence"] = error
        result["open_source"] = "error"
        return result

    result["http_status"] = resp.status_code

    if advanced:
        lib_hits = match_library_signatures(resp)
        result["frameworks_libraries"] = "; ".join(sorted(sig["name"] for sig, _ in lib_hits))

    hits = match_signatures(resp)
    if hits:
        sig, evidence = max(hits, key=lambda h: h[0].get("weight", 10))
        result["platform"] = sig["name"]
        result["open_source"] = "yes" if sig["open_source"] else "no"
        # If several platforms matched, note the others in the evidence.
        others = [s["name"] for s, _ in hits if s["name"] != sig["name"]]
        result["evidence"] = evidence + (f" (also: {', '.join(others)})" if others else "")
        return result

    if use_probe:
        probed = probe(url)
        if probed:
            name, open_source, evidence = probed
            result["platform"] = name
            result["open_source"] = "yes" if open_source else "no"
            result["evidence"] = evidence
            return result

    # Nothing matched. Note the server header as a weak hint.
    server = resp.headers.get("Server", "")
    result["evidence"] = f"no CMS signature matched (Server: {server or 'n/a'})"
    return result


def print_table(rows, advanced=False):
    """Print an aligned summary table to the console."""
    headers = ["HOSTNAME", "PLATFORM", "OPEN SOURCE?", "EVIDENCE"]
    cols = [
        [r["hostname"] for r in rows],
        [r["platform"] for r in rows],
        [r["open_source"] for r in rows],
        [r["evidence"] for r in rows],
    ]
    if advanced:
        headers.append("FRAMEWORKS/LIBRARIES")
        cols.append([r.get("frameworks_libraries", "") for r in rows])

    n = len(headers)
    widths = [
        max(len(headers[i]), *(len(str(v)) for v in cols[i])) if cols[i] else len(headers[i])
        for i in range(n)
    ]
    # Cap the evidence (and, in advanced mode, frameworks/libraries) columns
    # so the table stays readable.
    widths[3] = min(widths[3], 60)
    if advanced:
        widths[4] = min(widths[4], 60)

    def fmt(values):
        cells = []
        for i, v in enumerate(values):
            v = str(v)
            if i in (3, 4) and len(v) > widths[i]:
                v = v[: widths[i] - 1] + "…"
            cells.append(v.ljust(widths[i]))
        return "  ".join(cells).rstrip()

    print(fmt(headers))
    print("  ".join("-" * w for w in widths))
    for r in rows:
        row_values = [r["hostname"], r["platform"], r["open_source"], r["evidence"]]
        if advanced:
            row_values.append(r.get("frameworks_libraries", ""))
        print(fmt(row_values))


def write_csv(rows, path, advanced=False):
    fields = ["hostname", "http_status", "platform", "open_source", "evidence"]
    if advanced:
        fields.append("frameworks_libraries")
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Classify each site's CMS/platform as open source or proprietary."
    )
    parser.add_argument("input", nargs="?", default=INPUT,
                        help=f"text file with one domain/URL per line (default: {INPUT})")
    parser.add_argument("-o", "--output", default="output/TECHSTACK.csv",
                        help="CSV output path (default: output/TECHSTACK.csv)")
    parser.add_argument("--probe", action="store_true",
                        help="probe marker paths for sites with no signature match")
    parser.add_argument("--advanced", action="store_true",
                        help="also detect front-end frameworks/libraries (jQuery, React, "
                             "Google Analytics, Bootstrap, etc.) and add a "
                             "frameworks_libraries column")
    args = parser.parse_args(argv)

    try:
        sites = load_sites(args.input)
    except FileNotFoundError:
        sys.exit(f"Input file not found: {args.input}")

    if not sites:
        sys.exit(f"No sites found in {args.input}")

    rows = []
    for site in sites:
        print(f"auditing {site} ...", file=sys.stderr)
        rows.append(classify(site, use_probe=args.probe, advanced=args.advanced))

    print()
    print_table(rows, advanced=args.advanced)

    tally = {"yes": 0, "no": 0, "unknown": 0, "error": 0}
    for r in rows:
        tally[r["open_source"]] = tally.get(r["open_source"], 0) + 1
    print()
    print(
        f"Summary: {tally['yes']} open source, {tally['no']} proprietary, "
        f"{tally['unknown']} undetermined, {tally['error']} unreachable "
        f"(of {len(rows)} sites)"
    )

    write_csv(rows, args.output, advanced=args.advanced)
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()

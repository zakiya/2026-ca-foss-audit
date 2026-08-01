#!/usr/bin/env python3
"""Combine per-host event counts into registered-domain groups.

Reads INPUT (lines of `host,count`), groups *.ca.gov and *.ca.local hosts by
their registered domain (last 3 labels), and writes OUTPUT with the combined
counts and the list of source hosts that fed into each group.
"""

import re

INPUT = "input/sites-ga-events.csv"
OUTPUT = "output/sites-ga-condensed.csv"

QUOTE_RE = re.compile(r'[",\n;]')


def group_key(host):
    """Reduce a host to its 'registered domain' group key."""
    if host == "":
        return "(blank)"
    labels = host.split(".")
    n = len(labels)
    if n >= 3 and labels[n - 1] == "gov" and labels[n - 2] == "ca":
        return ".".join(labels[n - 3:])  # agency.ca.gov
    if n >= 3 and labels[n - 1] == "local" and labels[n - 2] == "ca":
        return ".".join(labels[n - 3:])  # agency.ca.local
    return host  # everything else: exact-dedup only


def csv_field(value):
    s = str(value)
    if QUOTE_RE.search(s):
        return '"' + s.replace('"', '""') + '"'
    return s


def main():
    with open(INPUT, encoding="utf-8") as fh:
        lines = [line for line in fh.read().split("\n") if line]

    # key -> {"count": int, "sources": {source_host: count}}
    groups = {}
    input_count = 0
    input_total = 0
    unique_hosts = set()

    for line in lines:
        comma = line.find(",")
        if comma == -1:
            continue
        host = line[:comma]
        try:
            count = int(line[comma + 1:])
        except ValueError:
            continue

        input_count += 1
        input_total += count
        unique_hosts.add(host)

        key = group_key(host)
        g = groups.setdefault(key, {"count": 0, "sources": {}})
        g["count"] += count
        g["sources"][host] = g["sources"].get(host, 0) + count

    rows = []
    for key, g in groups.items():
        sources = sorted(g["sources"].items(), key=lambda kv: (-kv[1], kv[0]))
        sources_str = "; ".join(("(blank)" if h == "" else h) for h, _ in sources)
        rows.append({"key": key, "count": g["count"], "sources": sources_str})
    rows.sort(key=lambda r: (-r["count"], r["key"]))

    out_lines = ["registered_domain,count,source_hosts"]
    for r in rows:
        out_lines.append(
            ",".join([csv_field(r["key"]), str(r["count"]), csv_field(r["sources"])])
        )
    with open(OUTPUT, "w", encoding="utf-8") as fh:
        fh.write("\n".join(out_lines) + "\n")

    output_total = sum(r["count"] for r in rows)
    print(f"Input rows parsed : {input_count}")
    print(f"Unique raw hosts  : {len(unique_hosts)}")
    print(f"Output rows       : {len(rows)}")
    print(f"Count total in    : {input_total}")
    conserved = "conserved ✓" if output_total == input_total else "MISMATCH ✗"
    print(f"Count total out   : {output_total}  ({conserved})")
    print(f"Wrote             : {OUTPUT}")

    merged = [r for r in rows if "; " in r["sources"]]
    print(f"\nGroups merging >1 source host: {len(merged)}")
    for r in merged[:10]:
        print(f"  {r['key']} ({r['count']}) <- {r['sources']}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Compare engine alerts against tests/pcaps/expected.json.

Usage: python3 tests/check.py PCAPDIR RESULTSDIR

RESULTSDIR holds one subdirectory per engine (suricata/, snort3/) with a
<case>.alerts fast-log file per pcap, as written by tests/engine.sh. Every case
must raise exactly its expected set of ELITEWOLF SIDs; anything missing or
extra is a failure, and every SID in rules/<engine>/elitewolf.rules must have
at least one positive case. Engines whose result directory is absent are
skipped.
"""

import json
import os
import re
import sys

SID_RE = re.compile(r"\[1:(\d+):\d+\]")
RULE_SID_RE = re.compile(r"^alert .*\bsid:(\d+);", re.M)
RULES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "rules")
ENGINES = ("suricata", "snort3")


def fired(path):
    sids = set()
    with open(path) as f:
        for line in f:
            for m in SID_RE.finditer(line):
                sid = int(m.group(1))
                if sid >= 1000000:
                    sids.add(sid)
    return sids


def main():
    pcapdir, resdir = sys.argv[1], sys.argv[2]
    with open(os.path.join(pcapdir, "expected.json")) as f:
        expected = json.load(f)

    failures = 0
    ran = 0
    for engine in ENGINES:
        edir = os.path.join(resdir, engine)
        if not os.path.isdir(edir):
            print(f"skip {engine}: no results in {edir}")
            continue
        ran += 1
        covered = set()
        for name in sorted(expected):
            want = set(expected[name][engine])
            path = os.path.join(edir, name + ".alerts")
            if not os.path.exists(path):
                print(f"FAIL {engine:8} {name}: no output")
                failures += 1
                continue
            got = fired(path)
            covered |= got
            if got == want:
                print(f"ok   {engine:8} {name}: {sorted(got) or '-'}")
            else:
                print(f"FAIL {engine:8} {name}: want {sorted(want)} got {sorted(got)}"
                      f" (missing {sorted(want - got)}, extra {sorted(got - want)})")
                failures += 1
        with open(os.path.join(RULES, engine, "elitewolf.rules")) as f:
            rule_sids = {int(s) for s in RULE_SID_RE.findall(f.read())}
        positive = set()
        for name in expected:
            positive |= set(expected[name][engine])
        untested = rule_sids - positive
        if untested:
            print(f"FAIL {engine:8} rules with no positive case: {sorted(untested)}")
            failures += 1
        print(f"{engine}: {len(rule_sids)} rules, {len(covered)} distinct SIDs fired"
              f" across {len(expected)} pcaps")

    if not ran:
        print("no engine results found")
        return 1
    print(f"{failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

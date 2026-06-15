#!/usr/bin/env python3
"""
get_timestomp_candidates — disk-side timestomp detector for the Find Evil! agent.

Detects MFT entries whose $STANDARD_INFORMATION (the visible, easily-modified) creation
time is BACKDATED relative to the $FILE_NAME creation time — the signature of timestomping
(MITRE T1070.006).

Why $SI vs $FN
--------------
A normally-created file gets IDENTICAL $SI and $FN creation times. Anti-forensic tools
(timestomp, SetMACE) rewrite the $SI timestamps to make a payload look old and blend with
system files, but the $FN timestamps — stored in the parent directory index and only
refreshed on create/rename/move — retain the true, recent time. So:

        $SI.crtime  <<  $FN.crtime        ==>  the file claims to be older than it is.

Input
-----
A TSK mactime *bodyfile* produced by:  sudo fls -r -m C: <image>
fls emits two lines per file: a $SI line and a " ($FILE_NAME)" line. They share the base
MFT entry number but differ in TSK's attribute-suffixed inode field
(e.g. 376952-128-4 for $DATA vs 376952-48-2 for $FILE_NAME), so we pair on the entry
number before the first '-'.

Discrimination (the whole point — see 05_BUILD_LOG false-positive finding)
--------------------------------------------------------------------------
Naive "$SI < $FN" returns ~157k hits on ROCBA, nearly all benign application-cache files
that wrote a NULL ($SI≈epoch-0) creation time. We therefore:
  * drop null-$SI entries (crtime at/near epoch 0) — app artifact, not a timestomp;
  * down-rank known cache/servicing NOISE directories;
  * up-rank executables/scripts (where payloads hide) → HIGH confidence;
  * require a meaningful backdate delta;
and emit a confidence label so the agent corroborates HIGH hits against memory (process
start time vs the recent $FN creation) before concluding. Bulk filtering is NOT enough;
the value is in returning the few anomalies, not the millions of rows.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone

# crtime at/below this epoch is treated as NULL (app wrote no real $SI creation time).
# 1980-01-01 UTC — well before any plausible backdated-but-real timestamp on a 2020 host.
NULL_SI_EPOCH = 315_532_800

# Substrings (case-insensitive) of paths that are high-volume benign churn. A real payload
# does NOT live in a browser/Office cache or the servicing store, so these never rate HIGH.
NOISE_DIR_PATTERNS = [
    "cache2", "/code cache/", "/cache/", "cachestorage", "gpucache", "service worker",
    "/inetcache/", "tapcache", "/winsxs/", "/servicing/", "softwaredistribution",
    "/assembly/", "/installer/", "apprepository", "definition updates", "/thumbcache",
    "/explorer/", "/edge/user data/", "/chrome/user data/", "/mozilla/firefox/profiles/",
]

# Extensions where a timestomp is high-signal (executable / script payloads).
EXEC_EXTS = {
    ".exe", ".dll", ".sys", ".ps1", ".bat", ".scr", ".vbs", ".com", ".cpl", ".jar", ".js",
}

# User-writable roots where a dropped payload realistically lives. An executable backdated
# HERE is far more suspicious than one in Program Files / Windows (legit install targets).
USER_WRITABLE_PATTERNS = [
    "/users/", "/programdata/", "/temp/", "/tmp/", "/public/", "/appdata/",
    "/$recycle.bin/", "/perflogs/", "/windows.old/users/",
]

# If this many files share the EXACT same $SI creation second, it's installer/media
# extraction (e.g. the famous 2002-02-01 Office/VSTO media date), not per-file timestomping.
# A real timestomp backdates one or a few files, never hundreds to the identical second.
CLUSTER_THRESHOLD = 8

FN_TAG = re.compile(r"\s*\(\$FILE_NAME\)\s*$")


@dataclass
class Candidate:
    mft_entry: str
    path: str
    ext: str
    confidence: str          # high | medium | noise | null_si
    backdate_days: float     # how much older $SI claims to be than $FN
    si_crtime: str           # ISO8601 UTC (visible/forged creation)
    fn_crtime: str           # ISO8601 UTC (true creation)
    si_mtime: str            # context: visible modified
    si_atime: str            # context: visible accessed
    provenance: str          # artifact ref for the audit trail


def _iso(epoch: float) -> str:
    try:
        return datetime.fromtimestamp(int(epoch), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, OverflowError, OSError):
        return "invalid"


def parse_bodyfile(path: str) -> dict[str, dict]:
    """Parse a TSK mactime bodyfile into {mft_entry: {path, si:{...}, fn_crtime}}.

    Bodyfile fields (|-separated): md5|name|inode|mode|uid|gid|size|atime|mtime|ctime|crtime
    """
    entries: dict[str, dict] = {}
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            parts = line.rstrip("\n").split("|")
            if len(parts) < 11:
                continue
            name, inode = parts[1], parts[2]
            try:
                atime, mtime, _ctime, crtime = (float(parts[7]), float(parts[8]),
                                                float(parts[9]), float(parts[10]))
            except ValueError:
                continue
            mft_entry = inode.split("-", 1)[0]
            rec = entries.setdefault(mft_entry, {"path": None, "si": None, "fn_crtime": None})
            if FN_TAG.search(name):
                rec["fn_crtime"] = crtime
                clean = FN_TAG.sub("", name)
                if rec["path"] is None:
                    rec["path"] = clean
            else:
                rec["si"] = {"crtime": crtime, "mtime": mtime, "atime": atime}
                rec["path"] = name
    return entries


def _ext(path: str) -> str:
    base = path.rsplit("/", 1)[-1]
    return ("." + base.rsplit(".", 1)[1].lower()) if "." in base else ""


def _classify(path: str, ext: str, si_crtime: float, is_cluster: bool) -> str:
    """Confidence label. Order matters — exclusions first, then signal."""
    if si_crtime <= NULL_SI_EPOCH:
        return "null_si"                      # app wrote no real $SI creation time
    lower = path.lower()
    if any(p in lower for p in NOISE_DIR_PATTERNS):
        return "noise"                        # browser/Office cache churn
    if is_cluster:
        return "installer"                    # many files share this exact $SI second
    user_writable = any(p in lower for p in USER_WRITABLE_PATTERNS)
    if ext in EXEC_EXTS:
        return "high" if user_writable else "medium"   # payload in a writable dir = HIGH
    return "low"


def get_timestomp_candidates(
    bodyfile: str,
    min_delta_days: float = 1.0,
    include_excluded: bool = False,
    fn_after: float | None = None,
) -> dict:
    """Return discriminated timestomp candidates from a bodyfile.

    Args:
        bodyfile: path to a TSK mactime bodyfile (sudo fls -r -m C: <image>).
        min_delta_days: minimum $FN−$SI backdate (days) to consider.
        include_excluded: also return the null_si / noise buckets (default: drop them).
        fn_after: if set, only files whose TRUE ($FN) creation is at/after this epoch —
                  e.g. the incident window, "what was really created during the absence".

    Returns dict with a `summary` and `candidates` (sorted by backdate, HIGH first).
    """
    entries = parse_bodyfile(bodyfile)
    min_delta = min_delta_days * 86400.0
    buckets = {"high": 0, "medium": 0, "low": 0, "installer": 0, "noise": 0, "null_si": 0}
    paired = 0
    out: list[Candidate] = []

    # Pass 1: among backdated, non-null entries, count how many files share each exact $SI
    # second. A shared second across many files = installer/media extraction, not timestomping.
    si_freq: dict[float, int] = {}
    for rec in entries.values():
        si, fn_cr = rec["si"], rec["fn_crtime"]
        if not si or fn_cr is None:
            continue
        if fn_cr - si["crtime"] > min_delta and si["crtime"] > NULL_SI_EPOCH:
            si_freq[si["crtime"]] = si_freq.get(si["crtime"], 0) + 1

    EXCLUDED = ("null_si", "noise", "installer")
    for mft_entry, rec in entries.items():
        si, fn_cr, path = rec["si"], rec["fn_crtime"], rec["path"]
        if not si or fn_cr is None or path is None:
            continue
        paired += 1
        delta = fn_cr - si["crtime"]          # >0 => $SI older than $FN => backdated
        if delta <= min_delta:
            continue
        if fn_after is not None and fn_cr < fn_after:
            continue
        ext = _ext(path)
        is_cluster = si_freq.get(si["crtime"], 0) >= CLUSTER_THRESHOLD
        conf = _classify(path, ext, si["crtime"], is_cluster)
        buckets[conf] += 1
        if conf in EXCLUDED and not include_excluded:
            continue
        out.append(Candidate(
            mft_entry=mft_entry,
            path=path,
            ext=ext,
            confidence=conf,
            backdate_days=round(delta / 86400.0, 2),
            si_crtime=_iso(si["crtime"]),
            fn_crtime=_iso(fn_cr),
            si_mtime=_iso(si["mtime"]),
            si_atime=_iso(si["atime"]),
            provenance=f"$MFT entry {mft_entry}: $SI.crtime vs $FN.crtime (TSK fls bodyfile)",
        ))

    rank = {"high": 0, "medium": 1, "low": 2, "installer": 3, "noise": 4, "null_si": 5}
    out.sort(key=lambda c: (rank[c.confidence], -c.backdate_days))

    return {
        "summary": {
            "paired_mft_entries": paired,
            "backdated_total": sum(buckets.values()),
            "by_confidence": buckets,
            "returned": len(out),
            "note": "HIGH = executable, non-cache, real (non-null) $SI — corroborate vs memory "
                    "process start before concluding. null_si/noise are the benign FP buckets.",
        },
        "candidates": [asdict(c) for c in out],
    }


def _main() -> int:
    ap = argparse.ArgumentParser(description="Detect timestomp candidates ($SI backdated vs $FN) from a TSK bodyfile.")
    ap.add_argument("bodyfile", help="TSK mactime bodyfile (sudo fls -r -m C: <image>)")
    ap.add_argument("--min-delta-days", type=float, default=1.0)
    ap.add_argument("--include-excluded", action="store_true", help="also emit null_si/noise buckets")
    ap.add_argument("--fn-after", help="only TRUE creations at/after this UTC date, e.g. 2020-11-09")
    ap.add_argument("--limit", type=int, default=0, help="cap candidates in output (0 = all)")
    args = ap.parse_args()

    fn_after = None
    if args.fn_after:
        fn_after = datetime.strptime(args.fn_after, "%Y-%m-%d").replace(tzinfo=timezone.utc).timestamp()

    result = get_timestomp_candidates(
        args.bodyfile,
        min_delta_days=args.min_delta_days,
        include_excluded=args.include_excluded,
        fn_after=fn_after,
    )
    if args.limit:
        result["candidates"] = result["candidates"][: args.limit]
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())

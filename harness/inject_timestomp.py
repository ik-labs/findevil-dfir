#!/usr/bin/env python3
"""
inject_timestomp.py — plant a TIMESTOMP contradiction by editing a real $MFT (T1070.006).

TEST HARNESS, not part of the agent. Backdates the $STANDARD_INFORMATION ($SI) creation
timestamp of one MFT record while leaving $FILE_NAME ($FN) intact — reproducing exactly what
an attacker does with timestomp/SetMACE. We operate on an EXTRACTED $MFT copy (icat <img> 0),
never the original evidence. In an extracted $MFT, record N lives at byte offset N*1024, so
no data-run resolution is needed.

NTFS layout used here (all little-endian):
  MFT record:  [0:4]="FILE"  [20:22]=offset to first attribute
  attribute:   [0:4]=type (0x10=$STD_INFO, 0x30=$FILE_NAME, 0xFFFFFFFF=end)  [4:8]=length
               [8]=non-resident flag  [20:22]=offset to resident content
  $SI content: [0:8]=creation  [8:16]=modified  [16:24]=mft-modified  [24:32]=accessed
  $FN content: [0:8]=parent ref ... [8:16]=creation ...   (we READ $FN, never write it)

Timestamps are Windows FILETIME (100-ns ticks since 1601-01-01 UTC).
"""

from __future__ import annotations

import argparse
import struct
import sys
from datetime import datetime, timezone

RECORD_SIZE = 1024
FILETIME_EPOCH_DIFF = 11_644_473_600  # seconds between 1601-01-01 and 1970-01-01
TYPE_SI, TYPE_FN, TYPE_END = 0x10, 0x30, 0xFFFFFFFF


def dt_to_filetime(dt: datetime) -> int:
    return int((dt.replace(tzinfo=timezone.utc).timestamp() + FILETIME_EPOCH_DIFF) * 10_000_000)


def filetime_to_iso(ft: int) -> str:
    try:
        return datetime.fromtimestamp(ft / 10_000_000 - FILETIME_EPOCH_DIFF, tz=timezone.utc) \
            .strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, OverflowError, OSError):
        return f"invalid(0x{ft:x})"


def _iter_attrs(rec: bytes):
    """Yield (attr_type, attr_abs_offset, content_abs_offset) for resident attributes."""
    first = struct.unpack_from("<H", rec, 20)[0]
    off = first
    while off + 8 <= len(rec):
        atype = struct.unpack_from("<I", rec, off)[0]
        if atype == TYPE_END:
            break
        alen = struct.unpack_from("<I", rec, off + 4)[0]
        if alen == 0:
            break
        non_resident = rec[off + 8]
        content_off = None
        if non_resident == 0:
            content_off = off + struct.unpack_from("<H", rec, off + 20)[0]
        yield atype, off, content_off
        off += alen


def read_record(path: str, entry: int) -> bytes:
    with open(path, "rb") as fh:
        fh.seek(entry * RECORD_SIZE)
        rec = fh.read(RECORD_SIZE)
    if rec[:4] != b"FILE":
        raise ValueError(f"MFT entry {entry}: no FILE signature (got {rec[:4]!r}) — wrong offset/fragmented?")
    return rec


def get_times(rec: bytes) -> dict:
    out = {"si_creation": None, "fn_creation": None, "si_content_off": None}
    for atype, _aoff, coff in _iter_attrs(rec):
        if coff is None:
            continue
        if atype == TYPE_SI and out["si_content_off"] is None:
            out["si_content_off"] = coff
            out["si_creation"] = struct.unpack_from("<Q", rec, coff)[0]
        elif atype == TYPE_FN and out["fn_creation"] is None:
            out["fn_creation"] = struct.unpack_from("<Q", rec, coff + 8)[0]
    return out


def inject(path: str, entry: int, new_si_creation: datetime, dry_run: bool = False) -> dict:
    rec = bytearray(read_record(path, entry))
    t = get_times(rec)
    if t["si_content_off"] is None:
        raise ValueError(f"MFT entry {entry}: no resident $STANDARD_INFORMATION attribute found")
    before = {"si_creation": filetime_to_iso(t["si_creation"]),
              "fn_creation": filetime_to_iso(t["fn_creation"]) if t["fn_creation"] else None}
    new_ft = dt_to_filetime(new_si_creation)
    struct.pack_into("<Q", rec, t["si_content_off"], new_ft)
    if not dry_run:
        with open(path, "r+b") as fh:
            fh.seek(entry * RECORD_SIZE + t["si_content_off"])
            fh.write(struct.pack("<Q", new_ft))
    after = get_times(rec)
    return {
        "entry": entry,
        "si_content_byte_offset_in_record": t["si_content_off"],
        "si_creation_before": before["si_creation"],
        "si_creation_after": filetime_to_iso(after["si_creation"]),
        "fn_creation": before["fn_creation"],     # unchanged — the truth the forgery can't reach
        "applied": not dry_run,
    }


def _main() -> int:
    ap = argparse.ArgumentParser(description="Backdate $SI creation of one MFT entry (timestomp).")
    ap.add_argument("mft", help="extracted $MFT file (icat <image> 0)")
    ap.add_argument("entry", type=int, help="MFT entry number to timestomp")
    ap.add_argument("--set-si-creation", required=True, help="backdated date, e.g. 2019-03-15 or 2019-03-15T08:00:00")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    fmt = "%Y-%m-%dT%H:%M:%S" if "T" in args.set_si_creation else "%Y-%m-%d"
    new_dt = datetime.strptime(args.set_si_creation, fmt)
    result = inject(args.mft, args.entry, new_dt, dry_run=args.dry_run)
    import json
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())

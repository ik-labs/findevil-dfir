#!/usr/bin/env python3
"""
inject_masquerade.py — plant a MASQUERADE contradiction (MITRE T1036) by renaming a file's
$FILE_NAME in the $MFT to a trusted system-binary name, in place. Reproduces an attacker
dropping e.g. svchost.exe into a user directory to abuse name-based trust.

TEST HARNESS. Operates on an extracted $MFT copy (record N at byte N*1024). Only the $FN name
bytes + the name-length field change; the new name must be <= the old name length so no
attribute/record resizing is needed (we leave the trailing bytes; the parser stops at
name_length). Other attributes ($DATA content, $SI) are untouched.

$FILE_NAME content layout: ... [0x40]=name length (chars) [0x41]=namespace [0x42:]=UTF-16 name
"""

from __future__ import annotations

import argparse
import json
import struct
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from inject_timestomp import read_record, _iter_attrs, RECORD_SIZE, TYPE_FN  # noqa: E402


def _fn_names(rec: bytes) -> list[tuple[int, int, str]]:
    """Return [(name_len_byte_offset, name_offset, current_name)] for each resident $FN."""
    out = []
    for atype, _aoff, coff in _iter_attrs(rec):
        if atype == TYPE_FN and coff is not None:
            nlen = rec[coff + 64]
            name = rec[coff + 66:coff + 66 + nlen * 2].decode("utf-16le", "replace")
            out.append((coff + 64, coff + 66, name))
    return out


def rename(path: str, entry: int, new_name: str, dry_run: bool = False) -> dict:
    rec = bytearray(read_record(path, entry))
    fns = _fn_names(rec)
    if not fns:
        raise ValueError(f"entry {entry}: no resident $FILE_NAME attribute")
    new_utf16 = new_name.encode("utf-16le")
    before = [n for _, _, n in fns]
    for nlen_off, name_off, old in fns:
        if len(new_name) > len(old):
            raise ValueError(f"new name '{new_name}' ({len(new_name)}) longer than old "
                             f"'{old}' ({len(old)}) — in-place rename needs new <= old")
        rec[nlen_off] = len(new_name)
        rec[name_off:name_off + len(new_utf16)] = new_utf16
        if not dry_run:
            with open(path, "r+b") as fh:
                fh.seek(entry * RECORD_SIZE + nlen_off)
                fh.write(struct.pack("<B", len(new_name)))
                fh.seek(entry * RECORD_SIZE + name_off)
                fh.write(new_utf16)
    after = [n for _, _, n in _fn_names(rec)]
    return {"entry": entry, "fn_names_before": before, "fn_names_after": after,
            "applied": not dry_run}


def _main() -> int:
    ap = argparse.ArgumentParser(description="Rename an MFT entry's $FN to a system-binary name (masquerade).")
    ap.add_argument("mft")
    ap.add_argument("entry", type=int)
    ap.add_argument("--to", required=True, help="new filename, e.g. svchost.exe")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    json.dump(rename(args.mft, args.entry, args.to, args.dry_run), sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())

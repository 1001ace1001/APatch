#!/usr/bin/env python3
"""Retarget the KernelPatch binaries at this fork's manager package and signing key.

The manager APK is located by PACKAGE NAME, not by scanning every installed app:
``find_trusted_manager_apk_path()`` walks ``/data/app`` and keeps the directory
whose name starts with ``<package>-``; the LKM does the same through
``kp_scan_apk_dir``. The expected signing certificate is stored next to that name
as a raw SHA-256 of the DER certificate. Both live inside the binaries, so a fork
that renames its applicationId or signs with its own key must rewrite them here.

kpimg (raw ARM64 image)
    struct trusted_manager_entry { char package[64]; uint8_t digest[32]; };
    Both fields are fixed-size, so they are overwritten in place.

*.ko (ET_REL aarch64 module)
    struct kp_trusted_manager { const char *package; const u8 digest[32]; };
    The digest is still inline, but the package is a pointer filled at load time
    by an R_AARCH64_ABS64 relocation: value = S + A. For a SECTION symbol S is 0,
    so A is an offset into that section. A longer name cannot grow in place, so
    it is written into an existing zero run and the relocation is retargeted.

The script is idempotent: re-running it on already patched files is a no-op.
"""

import argparse
import struct
import sys

SHT_NOBITS = 8
SHT_RELA = 4
SHT_SYMTAB = 2
SHF_ALLOC = 0x2
STT_SECTION = 3
R_AARCH64_ABS64 = 257


# ---------------------------------------------------------------- ELF helpers

def parse_sections(b):
    e_shoff = struct.unpack_from("<Q", b, 40)[0]
    e_shentsize = struct.unpack_from("<H", b, 58)[0]
    e_shnum = struct.unpack_from("<H", b, 60)[0]
    e_shstrndx = struct.unpack_from("<H", b, 62)[0]
    secs = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        secs.append(dict(
            idx=i,
            name_off=struct.unpack_from("<I", b, o)[0],
            type=struct.unpack_from("<I", b, o + 4)[0],
            flags=struct.unpack_from("<Q", b, o + 8)[0],
            offset=struct.unpack_from("<Q", b, o + 24)[0],
            size=struct.unpack_from("<Q", b, o + 32)[0],
            link=struct.unpack_from("<I", b, o + 40)[0],
            info=struct.unpack_from("<I", b, o + 44)[0],
            entsize=struct.unpack_from("<Q", b, o + 56)[0],
        ))
    if not secs or e_shstrndx >= len(secs):
        raise ValueError("not an ELF with a section header table")
    st = secs[e_shstrndx]
    for s in secs:
        end = b.find(b"\x00", st["offset"] + s["name_off"])
        s["name"] = b[st["offset"] + s["name_off"]:end].decode("ascii", "replace")
    return secs


def file_backed(s):
    return s["type"] != SHT_NOBITS and s["size"] > 0


def zero_runs(b, sec, minlen):
    out, i, end = [], sec["offset"], sec["offset"] + sec["size"]
    while i < end:
        if b[i] == 0:
            j = i
            while j < end and b[j] == 0:
                j += 1
            if j - i >= minlen:
                out.append((i - sec["offset"], j - i))
            i = j
        else:
            i += 1
    return out


def rela_targets(b, secs, sec_idx):
    """Offsets inside sec_idx that some relocation writes to, so they are in use."""
    used = set()
    for s in secs:
        if s["type"] != SHT_RELA or s["info"] != sec_idx:
            continue
        es = s["entsize"] or 24
        for i in range(s["size"] // es):
            used.add(struct.unpack_from("<Q", b, s["offset"] + i * es)[0])
    return used


def find_pkg_rela(b, secs, ptr_off):
    """Locate the relocation that fills the trusted-manager package pointer."""
    for s in secs:
        if s["type"] != SHT_RELA:
            continue
        es = s["entsize"] or 24
        for i in range(s["size"] // es):
            o = s["offset"] + i * es
            tgt = secs[s["info"]] if s["info"] < len(secs) else None
            if tgt is None or not file_backed(tgt):
                continue
            if tgt["offset"] + struct.unpack_from("<Q", b, o)[0] != ptr_off:
                continue
            r_info = struct.unpack_from("<Q", b, o + 8)[0]
            addend = struct.unpack_from("<q", b, o + 16)[0]
            symtab = secs[s["link"]]
            so = symtab["offset"] + (r_info >> 32) * (symtab["entsize"] or 24)
            st_value = struct.unpack_from("<Q", b, so + 8)[0]
            st_shndx = struct.unpack_from("<H", b, so + 6)[0]
            tsec = secs[st_shndx] if 0 < st_shndx < len(secs) else tgt
            return dict(rela_off=o, rtype=r_info & 0xFFFFFFFF, symtab=symtab,
                        addend=addend, tsec=tsec, toff=st_value + addend)
    return None


def section_symbols(b, secs, symtab):
    """Map section index -> symbol index for the SECTION symbols in symtab."""
    out = {}
    es = symtab["entsize"] or 24
    for i in range(symtab["size"] // es):
        o = symtab["offset"] + i * es
        if (b[o + 4] & 0xF) != STT_SECTION:
            continue
        shndx = struct.unpack_from("<H", b, o + 6)[0]
        if 0 < shndx < len(secs):
            out.setdefault(shndx, i)
    return out


def pick_slot(b, secs, rela, need):
    """Choose (sym_idx, section, offset) for the new package string."""
    t = rela["tsec"]
    used = rela_targets(b, secs, t["idx"])
    for off, ln in zero_runs(b, t, need):
        if not any(off <= u < off + ln for u in used):
            return 0, t, off
    syms = section_symbols(b, secs, rela["symtab"])
    for s in secs:
        if s["name"] != ".rodata" or not file_backed(s) or not (s["flags"] & SHF_ALLOC):
            continue
        if s["idx"] not in syms:
            continue
        used = rela_targets(b, secs, s["idx"])
        for off, ln in zero_runs(b, s, need):
            if not any(off <= u < off + ln for u in used):
                return syms[s["idx"]], s, off
    return None


# ------------------------------------------------------------------ patchers

def patch_kpimg(b, package, new_digest, old_digest):
    """kpimg: fixed-size package[64] followed by digest[32]."""
    changed = []

    # The digest sits right after the package field.
    for probe in (new_digest, old_digest):
        d = b.find(probe)
        if d >= 0:
            break
    else:
        raise SystemExit("kpimg: neither the old nor the new digest was found")
    pkg_off = d - 64
    if pkg_off < 0:
        raise SystemExit("kpimg: digest is too close to the start of the file")

    cur = bytes(b[pkg_off:pkg_off + 64]).split(b"\x00")[0].decode("ascii", "replace")
    if cur != package:
        enc = package.encode() + b"\x00"
        if len(enc) > 64:
            raise SystemExit("kpimg: %r does not fit the 64-byte package field" % package)
        b[pkg_off:pkg_off + 64] = enc + b"\x00" * (64 - len(enc))
        changed.append("package %r -> %r" % (cur, package))

    if bytes(b[d:d + 32]) != new_digest:
        b[d:d + 32] = new_digest
        changed.append("digest -> %s" % new_digest.hex()[:16])

    return changed


def patch_ko(b, secs, package, new_digest, old_digest):
    """ko: digest[32] preceded by a relocated `const char *package` pointer."""
    changed = []

    for probe in (new_digest, old_digest):
        d = b.find(probe)
        if d >= 0:
            break
    else:
        raise SystemExit("ko: neither the old nor the new digest was found")

    rela = find_pkg_rela(b, secs, d - 8)
    if rela is None:
        raise SystemExit("ko: no relocation fills the package pointer at digest-8")

    t = rela["tsec"]
    cur = bytes(b[t["offset"] + rela["toff"]:]).split(b"\x00")[0].decode("ascii", "replace")
    if cur != package:
        enc = package.encode() + b"\x00"
        slot = pick_slot(b, secs, rela, len(enc))
        if slot is None:
            raise SystemExit("ko: no free %d-byte slot for the package name" % len(enc))
        sym_idx, sec, off = slot
        b[sec["offset"] + off:sec["offset"] + off + len(enc)] = enc
        struct.pack_into("<q", b, rela["rela_off"] + 16, off)
        if sym_idx:
            struct.pack_into("<Q", b, rela["rela_off"] + 8,
                             (sym_idx << 32) | rela["rtype"])
        changed.append("package %r -> %r @%s+0x%x" % (cur, package, sec["name"], off))

    if bytes(b[d:d + 32]) != new_digest:
        b[d:d + 32] = new_digest
        changed.append("digest -> %s" % new_digest.hex()[:16])

    return changed


def is_elf(b):
    return len(b) > 64 and b[:4] == b"\x7fELF"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--package", required=True, help="manager applicationId")
    ap.add_argument("--digest", required=True, help="SHA-256 of the signing cert DER, hex")
    ap.add_argument("--old-digest", default="7ade19fd170911884b632c20362364ca60dfb82ae48f309d6f21c8ebd1cfdae8",
                    help="digest shipped by upstream KernelPatch, used to locate the field")
    ap.add_argument("--kpimg", action="append", default=[], help="kpimg image to patch")
    ap.add_argument("--ko", action="append", default=[], help="kernelpatch .ko to patch")
    ap.add_argument("--check", action="store_true", help="report without writing")
    args = ap.parse_args()

    try:
        new_digest = bytes.fromhex(args.digest)
    except ValueError:
        raise SystemExit("--digest must be 64 hex characters")
    if len(new_digest) != 32:
        raise SystemExit("--digest must be 32 bytes (64 hex characters)")
    old_digest = bytes.fromhex(args.old_digest)

    targets = [(p, False) for p in args.kpimg] + [(p, True) for p in args.ko]
    if not targets:
        raise SystemExit("nothing to do: pass --kpimg and/or --ko")

    failed = False
    for path, is_ko in targets:
        short = path.replace("\\", "/").rsplit("/", 1)[-1]
        try:
            with open(path, "rb") as fh:
                b = bytearray(fh.read())
            if is_ko:
                if not is_elf(b):
                    raise SystemExit("not an ELF object")
                changed = patch_ko(b, parse_sections(b), args.package, new_digest, old_digest)
            else:
                changed = patch_kpimg(b, args.package, new_digest, old_digest)
            if changed:
                if not args.check:
                    with open(path, "wb") as fh:
                        fh.write(b)
                print("  %-40s %s" % (short, "; ".join(changed)))
            else:
                print("  %-40s already up to date" % short)
        except (SystemExit, ValueError) as exc:
            failed = True
            print("  %-40s FAILED: %s" % (short, exc), file=sys.stderr)

    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

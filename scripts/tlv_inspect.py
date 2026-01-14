#!/usr/bin/env python3
"""
MCUboot TLV inspector (defensive parser).

- Parses MCUboot header
- Detects & parses Protected TLVs (magic 0x6908) and Regular TLVs (magic 0x6907)
- Optionally verifies SHA-256 TLV against the bytes MCUboot hashes:
    header + payload + protected TLVs (regular TLVs are NOT included)

References:
  • MCUboot image validation & TLV structure:
      header → payload → [protected TLVs] → [regular TLVs]
    (protected TLVs are included in signature/hash calculation, regular TLVs aren’t)
    https://deepwiki.com/mcu-tools/mcuboot/3.1-image-validation
  • imgtool basics & TLV content (hash, keyhash/pubkey, signature types):
    https://docs.mcuboot.com/imgtool.html
"""

import sys
import struct
import hashlib
from typing import List, Tuple

# -------- MCUboot constants --------
IMG_MAGIC = 0x96F3B83D         # Image header magic (LE on disk)
TLV_INFO_MAGIC_REG = 0x6907    # Regular TLV info magic (LE)
TLV_INFO_MAGIC_PROT = 0x6908   # Protected TLV info magic (LE)

# TLV type mapping (common subset; extend if your build uses more)
TLV_TYPES = {
    0x0001: "KEYHASH",
    0x0010: "SHA256",
    0x0011: "SHA384",
    0x0012: "SHA512",
    0x0020: "KEYHASH",   # SHA-256 of public key
    0x0021: "PUBKEY",    # DER-encoded public key
    0x0025: "MLDSA44",    # DER-encoded public key
    0x0026: "MLDSA65",    # DER-encoded public key
    0x0027: "MLDSA87",    # DER-encoded public key
    0x0030: "RSA-SIG",
    0x0031: "ECDSA-SIG",
    0x0032: "ED25519-SIG",
    # If your fork adds ML-DSA signatures, you can add:
    # 0x0033: "ML-DSA-44-SIG",
}

# -------- Little-endian helpers --------
def read_u16le(b, off) -> Tuple[int, int]:
    if off + 2 > len(b):
        raise ValueError(f"u16 read past EOF at 0x{off:x}")
    return struct.unpack_from("<H", b, off)[0], off + 2

def read_u32le(b, off) -> Tuple[int, int]:
    if off + 4 > len(b):
        raise ValueError(f"u32 read past EOF at 0x{off:x}")
    return struct.unpack_from("<I", b, off)[0], off + 4

# -------- TLV block parser (defensive) --------
def parse_tlv_block(b: bytes, start: int) -> Tuple[int, List[Tuple[int, int, bytes]]]:
    """
    Parse one TLV info block at 'start':

      TLV-INFO: 2B magic (LE), 2B total_size (LE)
      TLVs:     [ 2B type, 2B len, len bytes ] repeated until total_size consumed

    Returns: (next_offset, list[(type, len, value)])
    """
    if start + 4 > len(b):
        raise ValueError(f"TLV info header truncated at 0x{start:x}")

    off = start
    tlv_magic, off = read_u16le(b, off)
    tlv_total, off = read_u16le(b, off)  # size of TLV area (after this header)

    if tlv_magic not in (TLV_INFO_MAGIC_REG, TLV_INFO_MAGIC_PROT):
        raise ValueError(f"Unexpected TLV info magic 0x{tlv_magic:04x} at 0x{start:x}")

    # Clamp end to file length (prevents out-of-bounds)
    end = min(off + tlv_total, len(b))
    entries: List[Tuple[int, int, bytes]] = []

    # Iterate only while at least a TLV header fits
    while off < end:
        if off + 4 > end:
            break  # no room for (type,len)

        tlv_type, off = read_u16le(b, off)
        tlv_len,  off = read_u16le(b, off)

        if off + tlv_len > end:
            break  # truncated/corrupt TLV payload—stop cleanly

        tlv_val = b[off:off + tlv_len]
        off += tlv_len
        entries.append((tlv_type, tlv_len, tlv_val))

    return off, entries

# -------- Pretty-print helpers --------
def dump_entries(label: str, entries: List[Tuple[int, int, bytes]]) -> None:
    print(f"\n== {label} ==")
    if not entries:
        print("(none)")
        return
    for i, (t, L, v) in enumerate(entries):
        name = TLV_TYPES.get(t, f"UNKNOWN(0x{t:04x})")
        preview = v[:32]
        ell = "..." if L > 32 else ""
        print(f"[{i:02d}] type=0x{t:04x} ({name}) len={L}")
        print(f"     value[0:32]={preview.hex()}{ell}")

# -------- Image parser --------
def parse_mcuboot_image(path: str, verify_sha256: bool = True) -> None:
    with open(path, "rb") as f:
        data = f.read()

    # --- Image header (first 32 bytes) ---
    off = 0
    img_magic, off = read_u32le(data, off)
    if img_magic != IMG_MAGIC:
        raise ValueError(f"Not an MCUboot image: magic 0x{img_magic:08x}")

    load_addr, off      = read_u32le(data, off)   # typically 0
    hdr_size,   off     = read_u16le(data, off)   # e.g., 0x20 or padded 0x200
    prot_tlv_sz, off    = read_u16le(data, off)   # bytes of protected TLV block (0 if none)
    img_size,    off    = read_u32le(data, off)   # payload size (excl header)
    flags,       off    = read_u32le(data, off)
    # Version (8B) and padding (4B) follow; not needed here

    print(f"[Header] magic=0x{img_magic:08x} hdr_size=0x{hdr_size:x} "
          f"prot_tlv_size=0x{prot_tlv_sz:x} img_size=0x{img_size:x} flags=0x{flags:08x}")

    # Offsets
    payload_off = hdr_size
    tlv_off     = hdr_size + img_size
    cur         = tlv_off

    # --- Protected TLVs (optional) ---
    entries_prot: List[Tuple[int, int, bytes]] = []
    if prot_tlv_sz:
        # Make sure there's something that looks like a TLV info header
        if cur + 2 <= len(data):
            maybe_magic = struct.unpack_from("<H", data, cur)[0]
            if maybe_magic == TLV_INFO_MAGIC_PROT:
                try:
                    nxt, entries_prot = parse_tlv_block(data, cur)
                    print(f"[Protected TLVs] count={len(entries_prot)} bytes=0x{prot_tlv_sz:x}")
                    cur = nxt
                except Exception as e:
                    print(f"[Protected TLVs] parse error at 0x{cur:x}: {e}")
            else:
                print(f"[Protected TLVs] expected at 0x{cur:x}, but magic=0x{maybe_magic:04x}")
        else:
            print(f"[Protected TLVs] none (offset 0x{cur:x} at EOF)")

    # --- Regular TLVs (optional) ---
    entries_reg: List[Tuple[int, int, bytes]] = []
    if cur + 2 <= len(data):
        maybe_magic = struct.unpack_from("<H", data, cur)[0]
        if maybe_magic == TLV_INFO_MAGIC_REG:
            try:
                _, entries_reg = parse_tlv_block(data, cur)
                print(f"[Regular TLVs] count={len(entries_reg)}")
            except Exception as e:
                print(f"[Regular TLVs] parse error at 0x{cur:x}: {e}")
        else:
            # No regular TLV block here; could be padding/trailer
            print(f"[Regular TLVs] none at 0x{cur:x} (magic=0x{maybe_magic:04x})")
    else:
        print(f"[Regular TLVs] none (offset 0x{cur:x} at EOF)")

    dump_entries("Protected TLVs", entries_prot)
    dump_entries("Regular TLVs", entries_reg)

    # --- Optional: verify SHA-256 TLV ---
    if verify_sha256:
        # MCUboot hashes: header + payload + protected TLVs (regular TLVs excluded).
        # If no protected TLVs, hash = header + payload.
        hash_end = tlv_off + prot_tlv_sz if prot_tlv_sz else tlv_off
        if hash_end > len(data):
            hash_end = len(data)  # clamp just in case
        region = data[:hash_end]
        calc = hashlib.sha256(region).digest()

        # Find SHA-256 TLV (commonly in Regular TLVs; some stacks may place it elsewhere)
        sha_tlv = next((v for (t, L, v) in entries_reg if t == 0x0010 and L == 32), None)
        if sha_tlv is None:
            sha_tlv = next((v for (t, L, v) in entries_prot if t == 0x0010 and L == 32), None)

        if sha_tlv:
            ok = (sha_tlv == calc)
            print(f"\n[Verify] SHA-256 TLV {'matches' if ok else 'MISMATCH'}")
            if not ok:
                print(f"         tlv = {sha_tlv.hex()}")
                print(f"         calc= {calc.hex()}")
        else:
            print("\n[Verify] No SHA-256 TLV (type 0x0010) found; "
                  "signed with different --sha or placed elsewhere?")

    print("\nDone.")

# -------- Entry point --------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <signed_image.bin> [--no-verify]")
        sys.exit(2)

    img_path = sys.argv[1]
    do_verify = True
    if len(sys.argv) > 2 and sys.argv[2] == "--no-verify":
        do_verify = False

    parse_mcuboot_image(img_path, verify_sha256=do_verify)
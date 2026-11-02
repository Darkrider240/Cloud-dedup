"""
Core logic shared by the AWS client and the local benchmark (no AWS imports).

Convergent encryption scheme used in this project:
    K   = SHA-256(chunk)[:16]          (content-derived key)
    C   = SPECK-128/128-CBC_K(chunk)   (deterministic: fixed IV)
    tag = SHA-256(C)                   (public identifier / dedup index key)

The tag is derived from the CIPHERTEXT, not the plaintext. If the tag were
SHA-256(plaintext), the identifier would reveal the encryption key K, since
K is a prefix of that same hash.
"""

import hashlib
from speck_cipher import speck_encrypt, speck_decrypt

# ---------------- Content-defined chunking (Gear rolling hash) ----------------

def _build_gear_table():
    table = []
    for i in range(256):
        d = hashlib.sha256(b"gear-table-" + bytes([i])).digest()
        table.append(int.from_bytes(d[:8], "big"))
    return table

_GEAR = _build_gear_table()
_M64 = (1 << 64) - 1


def cdc_chunks(data: bytes, min_size=2048, avg_bits=13, max_size=16384):
    """
    Gear-hash content-defined chunking. A boundary is declared when the low
    `avg_bits` bits of the rolling hash are zero (average chunk ~ 2^avg_bits
    bytes beyond min_size). Because boundaries depend on local content, a
    small edit only changes the chunks near it.
    """
    mask = (1 << avg_bits) - 1
    n = len(data)
    chunks = []
    start = 0
    while start < n:
        end_limit = min(start + max_size, n)
        i = start + min_size
        if i >= end_limit:
            chunks.append(data[start:end_limit])
            start = end_limit
            continue
        h = 0
        cut = end_limit
        gear = _GEAR
        while i < end_limit:
            h = ((h << 1) + gear[data[i]]) & _M64
            i += 1
            if (h & mask) == 0:
                cut = i
                break
        chunks.append(data[start:cut])
        start = cut
    return chunks


def fixed_chunks(data: bytes, size=8192):
    return [data[i:i + size] for i in range(0, len(data), size)]


# ---------------- Convergent encryption primitives ----------------

def derive_key(chunk: bytes) -> bytes:
    return hashlib.sha256(chunk).digest()[:16]


def tag_of(ciphertext: bytes) -> str:
    return hashlib.sha256(ciphertext).hexdigest()


def encrypt_chunk(chunk: bytes):
    """Returns (key, ciphertext, tag)."""
    key = derive_key(chunk)
    ct = speck_encrypt(chunk, key)
    return key, ct, tag_of(ct)


def decrypt_chunk(ciphertext: bytes, key: bytes) -> bytes:
    return speck_decrypt(ciphertext, key)

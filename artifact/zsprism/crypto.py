"""Cryptographic building blocks of ZS-PRISM.

All primitives come from the `cryptography` package (OpenSSL backend):

* HKDF-SHA-256 (RFC 5869) expands one 32-byte master secret into
  domain-separated subkeys.
* AES-256 applied to single 128-bit blocks is used as a pseudorandom
  permutation (PRP).  A block packs a 96-bit row identifier and a 32-bit
  store index, so every (row, store) pair maps to a distinct handle and the
  proxy can invert any handle it receives.
* HMAC-SHA-256 (RFC 2104), truncated to 128 bits, tokenises direct
  identifiers for equality lookup.
* Additive 2-out-of-2 secret sharing over Z_q with q = 2^61 - 1 protects the
  numeric measure; shares are drawn from the OS CSPRNG (`secrets`).
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import struct
from typing import Iterable, List, Sequence, Tuple

import numpy as np
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

Q = (1 << 61) - 1            # share modulus (public); a Mersenne prime
RID_BYTES = 12               # 96-bit random logical row identifiers
HANDLE_BYTES = 16            # one AES block
MASTER_KEY_BYTES = 32
# Row identifiers as a numpy record: 64-bit high part (join key) + 32-bit low part.
RID = np.dtype([("a", ">u8"), ("b", ">u4")])


def rid_array(rids) -> np.ndarray:
    return np.frombuffer(b"".join(rids), dtype=RID) if rids else np.empty(0, RID)


def rid_key(r: np.ndarray) -> np.ndarray:
    return r["a"].astype(np.uint64)


def intersect(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """Intersection of two duplicate-free RID arrays (joined on the 64-bit key, then verified)."""
    _, ia, ib = np.intersect1d(rid_key(a), rid_key(b), assume_unique=True, return_indices=True)
    if not np.array_equal(a["b"][ia], b["b"][ib]):
        raise ValueError("64-bit key collision between distinct row identifiers")
    return a[ia]


def new_master_key() -> bytes:
    return secrets.token_bytes(MASTER_KEY_BYTES)


def hkdf(master: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(master)


def new_rids(n: int) -> List[bytes]:
    """Fresh 96-bit row identifiers; collision probability <= n^2 / 2^97."""
    return [secrets.token_bytes(RID_BYTES) for _ in range(n)]


class HandleCodec:
    """h(r, c) = AES_K(r || uint32(c)); invertible, store-specific handles."""

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("AES-256 key must be 32 bytes")
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        # ECB over independent single blocks is exactly blockwise PRP
        # evaluation; no block ever carries more than one (row, store) pair.
        self._enc = cipher.encryptor()
        self._dec = cipher.decryptor()

    def handles(self, rids: Sequence[bytes], store: int) -> List[bytes]:
        if not rids:
            return []
        tag = struct.pack(">I", store)
        out = self._enc.update(b"".join(r + tag for r in rids))
        return [out[i:i + 16] for i in range(0, len(out), 16)]

    def rids(self, handles: Sequence[bytes], store: int) -> List[bytes]:
        """Invert handles and reject any that were not issued for `store`."""
        if not handles:
            return []
        plain = self._dec.update(b"".join(handles))
        tag = struct.pack(">I", store)
        out = []
        for i in range(0, len(plain), 16):
            if plain[i + 12:i + 16] != tag:
                raise ValueError("handle does not belong to the addressed store")
            out.append(plain[i:i + 12])
        return out

    # ---- vectorised forms: one AES call over a contiguous buffer
    def handles_blob(self, rids: np.ndarray, store: int) -> bytes:
        n = len(rids)
        buf = np.empty((n, 16), dtype=np.uint8)
        buf[:, :12] = rids.view(np.uint8).reshape(n, 12)
        buf[:, 12:] = np.frombuffer(struct.pack(">I", store), dtype=np.uint8)
        return self._enc.update(buf.tobytes()) if n else b""

    def rids_blob(self, blob: bytes, store: int) -> np.ndarray:
        if not blob:
            return np.empty(0, RID)
        plain = np.frombuffer(self._dec.update(blob), dtype=np.uint8).reshape(-1, 16)
        if not (plain[:, 12:] == np.frombuffer(struct.pack(">I", store), dtype=np.uint8)).all():
            raise ValueError("handle does not belong to the addressed store")
        return np.ascontiguousarray(plain[:, :12]).view(RID).reshape(-1)

    def translate(self, handles: Sequence[bytes], src: int, dst: int) -> List[bytes]:
        return self.handles(self.rids(handles, src), dst)


class Tokenizer:
    def __init__(self, key: bytes):
        self._key = key

    def token(self, value: str) -> bytes:
        return hmac.new(self._key, value.encode(), hashlib.sha256).digest()[:16]


def share(values: Iterable[int]) -> Tuple[List[int], List[int]]:
    """Split each value v into (s0, s1) with s0 uniform and s0 + s1 = v mod Q."""
    s0, s1 = [], []
    for v in values:
        m = secrets.randbelow(Q)
        s0.append(m)
        s1.append((v - m) % Q)
    return s0, s1


def reconstruct(a: int, b: int) -> int:
    return (a + b) % Q


class KeyRing:
    """Everything a ZS-PRISM proxy persists: one 32-byte master secret."""

    def __init__(self, master: bytes):
        if len(master) != MASTER_KEY_BYTES:
            raise ValueError("master secret must be 32 bytes")
        self.master = master
        self.handles = HandleCodec(hkdf(master, b"zs-prism/v1/handle-prp"))
        self.tokens = Tokenizer(hkdf(master, b"zs-prism/v1/identifier-token"))

    @property
    def persistent_bytes(self) -> int:
        return len(self.master)

"""ZS-PRISM and the baseline systems evaluated in the paper.

Split configurations (identical placement, shares, executor and planner;
they differ *only* in how fragments of one record are linked):

* ``prp``     -- ZS-PRISM: handles derived with a keyed PRP; no per-record state.
* ``map``     -- per-store random handles; the proxy keeps rid<->handle maps.
* ``shared``  -- one tuple identifier shared by all stores (as in two-server
                 vertical partitioning); stateless but trivially joinable.

Single-provider encrypted baselines:

* ``CryptDBStyle``  -- deterministic equality tags (range by IN-expansion over
  the small age domain), Paillier ciphertexts aggregated by a provider-side
  UDF, and an AES-GCM ciphertext of every record.
* ``EncryptedScan`` -- AES-GCM records; the proxy downloads and decrypts all.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from typing import Dict, List, Optional, Sequence, Tuple

import msgpack
import numpy as np
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .crypto import RID, KeyRing, Q, hkdf, intersect, new_master_key, new_rids, rid_array, rid_key, share
from .data import ATTR_STORE, Query, Record
from .rpc import Cluster

BATCH = 20000

SCHEMA = [
    "CREATE TABLE t (k BLOB PRIMARY KEY, idt BLOB, age INT, sex TEXT, s INT) WITHOUT ROWID;"
    "CREATE INDEX t_idt ON t(idt); CREATE INDEX t_age ON t(age); CREATE INDEX t_sex ON t(sex);",
    "CREATE TABLE t (k BLOB PRIMARY KEY, education TEXT, marital TEXT, s INT) WITHOUT ROWID;"
    "CREATE INDEX t_edu ON t(education); CREATE INDEX t_mar ON t(marital);",
    "CREATE TABLE t (k BLOB PRIMARY KEY, occupation TEXT, race TEXT, country TEXT) WITHOUT ROWID;"
    "CREATE INDEX t_occ ON t(occupation); CREATE INDEX t_race ON t(race); CREATE INDEX t_cty ON t(country);",
]
SHARE_HOLDERS = (0, 1)


# --------------------------------------------------------------------------
# Linkage strategies
# --------------------------------------------------------------------------
class PRPLinkage:
    name = "ZS-PRISM"

    def __init__(self, keys: KeyRing):
        self.codec = keys.handles

    def assign(self, rids, store):
        return self.codec.handles(rids, store)

    def handles(self, rids, store):
        return self.codec.handles(rids, store)

    def rids(self, handles, store):
        return self.codec.rids(handles, store)

    def handles_blob(self, rids, store):
        return self.codec.handles_blob(rids, store)

    def rids_blob(self, blob, store):
        return self.codec.rids_blob(blob, store)

    def forget(self, rids):
        pass

    def state_bytes(self) -> int:
        return 0  # per-record state; the 32-byte master key is reported separately


class MapLinkage:
    name = "Map split"

    def __init__(self, n_stores: int = 3):
        self.fwd: List[Dict[bytes, bytes]] = [dict() for _ in range(n_stores)]
        self.rev: List[Dict[bytes, bytes]] = [dict() for _ in range(n_stores)]
        self._dirty = True

    def _index(self):
        """Sorted-array index over the maps (binary search, vectorised)."""
        if not self._dirty:
            return
        rids = list(self.fwd[0])
        self._R = rid_array(rids)
        self._rk_perm = np.argsort(rid_key(self._R), kind="stable")
        self._rk_sorted = rid_key(self._R)[self._rk_perm]
        self._H, self._hk_perm, self._hk_sorted = [], [], []
        for f in self.fwd:
            H = np.frombuffer(b"".join(f[r] for r in rids), dtype=np.uint8).reshape(-1, 16)
            k = H[:, :8].copy().view(">u8").reshape(-1).astype(np.uint64)
            perm = np.argsort(k, kind="stable")
            self._H.append(H)
            self._hk_perm.append(perm)
            self._hk_sorted.append(k[perm])
        self._dirty = False

    def handles_blob(self, rids, store):
        self._index()
        rows = self._rk_perm[np.searchsorted(self._rk_sorted, rid_key(rids))]
        if not np.array_equal(self._R[rows], rids):
            raise KeyError("unknown row identifier")
        return self._H[store][rows].tobytes()

    def rids_blob(self, blob, store):
        self._index()
        if not blob:
            return np.empty(0, RID)
        Hq = np.frombuffer(blob, dtype=np.uint8).reshape(-1, 16)
        kq = Hq[:, :8].copy().view(">u8").reshape(-1).astype(np.uint64)
        rows = self._hk_perm[store][np.searchsorted(self._hk_sorted[store], kq)]
        if not np.array_equal(self._H[store][rows], Hq):
            raise KeyError("unknown handle")
        return self._R[rows]

    def assign(self, rids, store):
        self._dirty = True
        hs = [secrets.token_bytes(16) for _ in rids]
        f, r = self.fwd[store], self.rev[store]
        for rid, h in zip(rids, hs):
            f[rid] = h
            r[h] = rid
        return hs

    def handles(self, rids, store):
        f = self.fwd[store]
        return [f[r] for r in rids]

    def rids(self, handles, store):
        r = self.rev[store]
        return [r[h] for h in handles]

    def forget(self, rids):
        self._dirty = True
        for f, r in zip(self.fwd, self.rev):
            for rid in rids:
                h = f.pop(rid, None)
                if h is not None:
                    r.pop(h, None)

    def state_bytes(self) -> int:
        """Compact lower bound: rid (12 B) + one 16-B handle per store, per row."""
        return len(self.fwd[0]) * (12 + 16 * len(self.fwd))

    def snapshot(self) -> bytes:
        rows = [(rid, *[f[rid] for f in self.fwd]) for rid in self.fwd[0]]
        return b"".join(b"".join(t) for t in rows)

    @classmethod
    def restore(cls, blob: bytes, n_stores: int = 3) -> "MapLinkage":
        m = cls(n_stores)
        w = 12 + 16 * n_stores
        for off in range(0, len(blob), w):
            rid = blob[off:off + 12]
            for s in range(n_stores):
                h = blob[off + 12 + 16 * s: off + 28 + 16 * s]
                m.fwd[s][rid] = h
                m.rev[s][h] = rid
        return m


class SharedLinkage:
    name = "Shared-TID split"
    PAD = b"\x00" * 4

    def assign(self, rids, store):
        return self.handles(rids, store)

    def handles(self, rids, store):
        return [r + self.PAD for r in rids]

    def rids(self, handles, store):
        return [h[:12] for h in handles]

    def handles_blob(self, rids, store):
        n = len(rids)
        buf = np.zeros((n, 16), dtype=np.uint8)
        buf[:, :12] = rids.view(np.uint8).reshape(n, 12)
        return buf.tobytes()

    def rids_blob(self, blob, store):
        if not blob:
            return np.empty(0, RID)
        P = np.frombuffer(blob, dtype=np.uint8).reshape(-1, 16)
        return np.ascontiguousarray(P[:, :12]).view(RID).reshape(-1)

    def forget(self, rids):
        pass

    def state_bytes(self) -> int:
        return 0


# --------------------------------------------------------------------------
# Split-store system (shared executor for all linkage strategies)
# --------------------------------------------------------------------------
def _modsum(v: np.ndarray) -> int:
    """Exact sum of uint64 values < 2^61, computed in 32-bit halves (no overflow)."""
    lo = int((v & np.uint64(0xFFFFFFFF)).sum(dtype=np.uint64))
    hi = int((v >> np.uint64(32)).sum(dtype=np.uint64))
    return (hi << 32) + lo


def _where(preds: List[Tuple[str, object]]):
    clauses, params = [], []
    for a, v in preds:
        if a == "age":
            clauses.append("age BETWEEN ? AND ?")
            params.extend(v)
        else:
            clauses.append(f"{a} = ?")
            params.append(v)
    return " AND ".join(clauses), params


class SplitSystem:
    """Trusted proxy over three providers."""

    def __init__(self, linkage: str, cluster: Cluster, keys: Optional[KeyRing] = None,
                 plan: str = "auto", bw_mbps: float = 0.0):
        self.keys = keys or KeyRing(new_master_key())
        self.link = {"prp": lambda: PRPLinkage(self.keys), "map": MapLinkage,
                     "shared": SharedLinkage}[linkage]()
        self.name = self.link.name
        self.c = cluster
        self.plan = plan
        self.bw_mbps = bw_mbps
        self.alpha_proxy = 0.5e-6      # defaults; replaced by calibrate()
        self.alpha_provider = 0.5e-6
        self._rtt = 1e-3               # running RTT estimate (soft state)
        self.last_plan: List = []
        for i, ddl in enumerate(SCHEMA):
            self.c.p[i].script(ddl)

    # ---------------------------------------------------------------- write
    def _rows(self, recs: Sequence[Record], rids: List[bytes], assign: bool):
        f = self.link.assign if assign else self.link.handles
        hs = [f(rids, s) for s in range(3)]
        s0, s1 = share(r.hours for r in recs)
        tok = self.keys.tokens.token
        r0 = [(hs[0][i], tok(r.pid), r.age, r.sex, s0[i]) for i, r in enumerate(recs)]
        r1 = [(hs[1][i], r.education, r.marital, s1[i]) for i, r in enumerate(recs)]
        r2 = [(hs[2][i], r.occupation, r.race, r.country) for i, r in enumerate(recs)]
        # Rows are clustered by handle (WITHOUT ROWID); arrival order is not stored.
        return sorted(r0), sorted(r1), sorted(r2)

    def insert(self, recs: Sequence[Record]) -> float:
        t0 = time.perf_counter()
        for off in range(0, len(recs), BATCH):
            chunk = recs[off:off + BATCH]
            rids = new_rids(len(chunk))
            r0, r1, r2 = self._rows(chunk, rids, assign=True)
            self.c.parallel([
                (0, "executemany", "INSERT INTO t VALUES (?,?,?,?,?)", r0),
                (1, "executemany", "INSERT INTO t VALUES (?,?,?,?)", r1),
                (2, "executemany", "INSERT INTO t VALUES (?,?,?,?)", r2),
            ])
        return (time.perf_counter() - t0) * 1e3

    def _lookup_rid(self, pid: str) -> Optional[bytes]:
        rows = self.c.p[0].execute("SELECT k FROM t WHERE idt = ?", [self.keys.tokens.token(pid)])
        return self.link.rids([rows[0][0]], 0)[0] if rows else None

    def update(self, pid: str, hours: int) -> bool:
        rid = self._lookup_rid(pid)
        if rid is None:
            return False
        s0, s1 = share([hours])          # both shares refreshed with fresh randomness
        h0, h1 = self.link.handles([rid], 0)[0], self.link.handles([rid], 1)[0]
        self.c.parallel([
            (0, "execute", "UPDATE t SET s = ? WHERE k = ?", [s0[0], h0]),
            (1, "execute", "UPDATE t SET s = ? WHERE k = ?", [s1[0], h1]),
        ])
        return True

    def delete(self, pid: str) -> bool:
        rid = self._lookup_rid(pid)
        if rid is None:
            return False
        self.c.parallel([(s, "execute", "DELETE FROM t WHERE k = ?", [self.link.handles([rid], s)[0]])
                         for s in range(3)])
        self.link.forget([rid])
        return True

    # ----------------------------------------------------------------- read
    def lookup(self, pid: str) -> Optional[Record]:
        rows = self.c.p[0].execute("SELECT k, age, sex, s FROM t WHERE idt = ?",
                                   [self.keys.tokens.token(pid)])
        if not rows:
            return None
        k0, age, sex, s0 = rows[0]
        rid = self.link.rids([k0], 0)[0]
        h1, h2 = self.link.handles([rid], 1)[0], self.link.handles([rid], 2)[0]
        r1, r2 = self.c.parallel([
            (1, "execute", "SELECT education, marital, s FROM t WHERE k = ?", [h1]),
            (2, "execute", "SELECT occupation, race, country FROM t WHERE k = ?", [h2]),
        ])
        edu, mar, s1 = r1[0]
        occ, race, cty = r2[0]
        return Record(pid, age, sex, edu, mar, occ, race, cty, (s0 + s1) % Q)

    def query(self, q: Query):
        if q.agg == "lookup":
            return self.lookup(q.pid)
        by_store: Dict[int, List] = {}
        for a, v in q.predicates():
            by_store.setdefault(ATTR_STORE[a], []).append((a, v))
        need_sum = q.agg == "avg"
        stores = sorted(by_store)
        if not stores:
            raise ValueError("query without predicates")

        # Single-fragment COUNT is answered by one provider.
        if len(stores) == 1 and not need_sum:
            w, p = _where(by_store[stores[0]])
            self.last_plan = ["local"]
            return (self.c.p[stores[0]].execute(f"SELECT COUNT(*) FROM t WHERE {w}", p)[0][0], None)

        shares: Dict[int, tuple] = {}

        def stage_sql(s, semi):
            w, p = _where(by_store[s])
            cols = "k, s" if (need_sum and s in SHARE_HOLDERS) else "k"
            semi_clause = "k IN (SELECT k FROM _cand) AND " if semi else ""
            return f"SELECT {cols} FROM t WHERE {semi_clause}{w}", p

        def ncol(s):
            return 2 if (need_sum and s in SHARE_HOLDERS) else 1

        def absorb(s, packed):
            rids = self.link.rids_blob(packed[0], s)
            if ncol(s) == 2:
                shares[s] = (rids, np.frombuffer(packed[1], dtype="<i8").astype(np.uint64))
            return rids

        def pushdown(cand, order):
            for st in order:
                if not len(cand):
                    break
                sql, p = stage_sql(st, True)
                res = self.c.p[st].cols(sql, p, cand=self.link.handles_blob(cand, st), ncol=ncol(st))
                cand = absorb(st, res["c"])
            return cand

        def fetch_all(order, cand=None):
            results = self.c.parallel([(st, "cols", *stage_sql(st, False), None, ncol(st)) for st in order])
            for st, res in zip(order, results):
                rids = absorb(st, res["c"])
                cand = rids if cand is None else intersect(cand, rids)
            return cand

        if len(stores) == 1:
            self.last_plan = ["single"] + stores
            cand = fetch_all(stores)
        elif self.plan == "broadcast":
            self.last_plan = ["broadcast"] + stores
            cand = fetch_all(stores)
        elif self.plan == "pushdown":
            order = self._probe(stores, by_store)
            sql, p = stage_sql(order[0], False)
            cand = pushdown(absorb(order[0], self.c.p[order[0]].cols(sql, p, None, ncol(order[0]))["c"]), order[1:])
            self.last_plan = ["pushdown"] + order
        else:
            cand = self._adaptive(stores, by_store, need_sum, stage_sql, absorb, pushdown, fetch_all, ncol)

        count = len(cand)
        if not need_sum:
            return (count, None)
        if count == 0:
            return (0, 0)
        total = 0
        for s in SHARE_HOLDERS:
            if s in shares:
                rids, vals = shares[s]
                _, _, ib = np.intersect1d(rid_key(cand), rid_key(rids), assume_unique=True, return_indices=True)
                if len(ib) != count:
                    raise RuntimeError("share missing for a selected row")
                total += _modsum(vals[ib])
        missing = [s for s in SHARE_HOLDERS if s not in shares]
        if missing:
            res = self.c.parallel([
                (s, "cols", "SELECT zs_modsum(s, ?) FROM t WHERE k IN (SELECT k FROM _cand)", [Q],
                 self.link.handles_blob(cand, s), 1) for s in missing])
            total += sum(int(np.frombuffer(r["c"][0], dtype="<i8")[0]) for r in res)
        return (count, total % Q)

    # -------------------------------------------------------------- planner
    # Wire sizes of one handle / one handle plus share in a MessagePack row.
    B_H, B_HS = 16, 24      # packed handle / handle + 64-bit share

    def _probe(self, stores, by_store):
        calls = []
        for s in stores:
            w, p = _where(by_store[s])
            calls.append((s, "execute", f"SELECT COUNT(*) FROM t WHERE {w}", p))
        counts = [r[0][0] for r in self.c.parallel(calls)]
        self._counts = dict(zip(stores, counts))
        return [s for _, s in sorted(zip(counts, stores))]

    def _per_handle(self, wire: int) -> float:
        rate = self.bw_mbps * 1e6 / 8 if self.bw_mbps else float("inf")
        return wire / rate + self.alpha_provider + self.alpha_proxy

    def _adaptive(self, stores, by_store, need_sum, stage_sql, absorb, pushdown, fetch_all, ncol):
        """Payload-carrying probe followed by a cost-based continuation.

        Round 1 asks every predicate store for its cardinality and, when that
        cardinality is at most tau = RTT / (per-handle cost), for the matching
        handles themselves: shipping them is then cheaper than a later round
        trip.  The remaining stores are finished either by semi-join pushdown
        in ascending cardinality or by one parallel fetch, whichever Eq. (cost)
        predicts to be faster; intermediate pushdown sizes use the classical
        attribute-independence estimate |C_i| = |C_{i-1}| c_i / N.  RTT is a running estimate (EWMA) maintained
        from observed round trips; it is soft state and never persisted.
        """
        wire = {s: (self.B_HS if (need_sum and s in SHARE_HOLDERS) else self.B_H) for s in stores}
        calls = []
        for s in stores:
            w, p = _where(by_store[s])
            sel, sp = stage_sql(s, False)
            tau = int(self._rtt / self._per_handle(wire[s]))
            calls.append((s, "probe_cols", f"SELECT COUNT(*) FROM t WHERE {w}", p, sel, sp, tau, ncol(s)))
        t0 = time.perf_counter()
        res = self.c.parallel(calls)
        shipped = sum(r[0] for r in res if r[1] is not None)
        elapsed = time.perf_counter() - t0
        sample = elapsed - shipped * max(self._per_handle(self.B_HS) - self.alpha_proxy, 0)
        self._rtt = 0.7 * self._rtt + 0.3 * max(sample, 1e-5)
        counts = {s: r[0] for s, r in zip(stores, res)}
        cand = None
        for s, r in zip(stores, res):
            if r[1] is not None:
                rids = absorb(s, r[1])
                cand = rids if cand is None else intersect(cand, rids)
        rest = sorted((s for s, r in zip(stores, res) if r[1] is None), key=lambda s: counts[s])
        got = [s for s in stores if s not in rest]
        if not rest or (cand is not None and not len(cand)):
            self.last_plan = ["probe+ship"] + got
            return cand
        cost_pd = self._cost_pushdown(None if cand is None else len(cand), rest, counts, wire)
        cost_bc = self._rtt + max(counts[s] * (self._per_handle(wire[s]) - self.alpha_proxy) for s in rest) \
            + self.alpha_proxy * sum(counts[s] for s in rest)
        if cost_bc < cost_pd:
            self.last_plan = ["probe+ship"] + got + ["fetch"] + rest
            return fetch_all(rest, cand)
        if cand is None:
            sql, p = stage_sql(rest[0], False)
            cand = absorb(rest[0], self.c.p[rest[0]].cols(sql, p, None, ncol(rest[0]))["c"])
            self.last_plan = ["probe", "pushdown"] + rest
            return pushdown(cand, rest[1:])
        self.last_plan = ["probe+ship"] + got + ["pushdown"] + rest
        return pushdown(cand, rest)

    def _table_size(self) -> int:
        """Cached relation size (soft state, refreshed every 256 queries)."""
        self._n_age = getattr(self, "_n_age", 256) + 1
        if self._n_age > 256:
            self._n_est = max(self.c.p[2].execute("SELECT COUNT(*) FROM t")[0][0], 1)
            self._n_age = 0
        return self._n_est

    def _cost_pushdown(self, cur, order, counts, wire) -> float:
        t = 0.0
        if cur is None:
            cur = counts[order[0]]
            t += self._rtt + cur * self._per_handle(wire[order[0]])
            order = order[1:]
        n = self._table_size()
        for s in order:
            nxt = cur * min(counts[s] / n, 1.0)        # attribute-independence estimate
            t += self._rtt + cur * self._per_handle(self.B_H) + nxt * self._per_handle(wire[s])
            cur = nxt
        return t

    def calibrate(self, n: int = 20000):
        """Measure per-handle provider and proxy costs on the current host.

        Run once after loading, with no emulated delay: a full packed fetch
        of store 2's handles gives the provider/transport cost per handle;
        inverting and re-deriving them gives the proxy cost per handle.
        """
        t0 = time.perf_counter()
        res = self.c.p[2].cols("SELECT k FROM t", [], None, 1)
        self.alpha_provider = max((time.perf_counter() - t0) / max(res["n"], 1), 1e-9)
        blob = res["c"][0][:16 * n]
        t0 = time.perf_counter()
        self.link.handles_blob(self.link.rids_blob(blob, 2), 1)
        self.alpha_proxy = max((time.perf_counter() - t0) / max(len(blob) // 16, 1), 1e-9)
        return self.alpha_proxy, self.alpha_provider

    def state_bytes(self) -> int:
        return self.link.state_bytes()


# --------------------------------------------------------------------------
# Single-provider encrypted baselines
# --------------------------------------------------------------------------
class _RecordCipher:
    def __init__(self, key: bytes):
        self.aead = AESGCM(key)

    def seal(self, r: Record) -> bytes:
        nonce = secrets.token_bytes(12)
        return nonce + self.aead.encrypt(nonce, msgpack.packb(list(r)), None)

    def open(self, blob: bytes) -> Record:
        return Record(*msgpack.unpackb(self.aead.decrypt(blob[:12], blob[12:], None)))


class CryptDBStyle:
    """One provider; DET equality tags + Paillier SUM UDF + AES-GCM rows."""

    COLS = ("age", "sex", "education", "marital", "occupation", "race", "country")

    def __init__(self, cluster: Cluster, hom: bool = True, paillier_bits: int = 2048):
        self.name = "DET+Paillier" if hom else "DET+AEAD"
        master = new_master_key()
        self.det_key = hkdf(master, b"det")
        self.rc = _RecordCipher(hkdf(master, b"row"))
        self.c = cluster
        self.hom = hom
        if hom:
            from phe import paillier
            self.pub, self.priv = paillier.generate_paillier_keypair(n_length=paillier_bits)
            self.n2 = self.pub.nsquare.to_bytes((self.pub.nsquare.bit_length() + 7) // 8, "big")
        cols = ", ".join(f"{a} BLOB" for a in self.COLS)
        idx = "".join(f"CREATE INDEX e_{a} ON e({a});" for a in self.COLS)
        self.c.p[0].script(f"CREATE TABLE e (idt BLOB, {cols}, hom BLOB, ct BLOB);"
                           f"CREATE INDEX e_idt ON e(idt);{idx}")

    def tag(self, attr: str, value) -> bytes:
        return hmac.new(self.det_key, f"{attr}\x1f{value}".encode(), hashlib.sha256).digest()[:16]

    def _enc_hom(self, v: int) -> bytes:
        ct = self.pub.encrypt(v).ciphertext(be_secure=True)
        return ct.to_bytes((ct.bit_length() + 7) // 8, "big")

    def _row(self, r: Record):
        tags = [self.tag(a, getattr(r, a)) for a in self.COLS]
        hom = self._enc_hom(r.hours) if self.hom else None
        return (self.tag("pid", r.pid), *tags, hom, self.rc.seal(r))

    def insert(self, recs: Sequence[Record]) -> float:
        t0 = time.perf_counter()
        marks = ",".join("?" * (len(self.COLS) + 3))
        for off in range(0, len(recs), BATCH):
            self.c.p[0].executemany(f"INSERT INTO e VALUES ({marks})",
                                    [self._row(r) for r in recs[off:off + BATCH]])
        return (time.perf_counter() - t0) * 1e3

    def _where(self, q: Query):
        clauses, params = [], []
        for a, v in q.predicates():
            if a == "age":
                tags = [self.tag("age", x) for x in range(v[0], v[1] + 1)]
                clauses.append(f"age IN ({','.join('?' * len(tags))})")
                params.extend(tags)
            else:
                clauses.append(f"{a} = ?")
                params.append(self.tag(a, v))
        return " AND ".join(clauses), params

    def query(self, q: Query):
        if q.agg == "lookup":
            rows = self.c.p[0].execute("SELECT ct FROM e WHERE idt = ?", [self.tag("pid", q.pid)])
            return self.rc.open(rows[0][0]) if rows else None
        w, p = self._where(q)
        if q.agg == "count":
            return (self.c.p[0].execute(f"SELECT COUNT(*) FROM e WHERE {w}", p)[0][0], None)
        if self.hom:
            agg, cnt = self.c.p[0].execute(f"SELECT paillier_sum(hom, ?), COUNT(*) FROM e WHERE {w}",
                                           [self.n2, *p])[0]
            if cnt == 0:
                return (0, 0)
            from phe import paillier
            total = self.priv.decrypt(paillier.EncryptedNumber(self.pub, int.from_bytes(agg, "big"), 0))
            return (cnt, total)
        rows = self.c.p[0].execute(f"SELECT ct FROM e WHERE {w}", p)
        return (len(rows), sum(self.rc.open(r[0]).hours for r in rows))

    def update(self, pid: str, hours: int) -> bool:
        rows = self.c.p[0].execute("SELECT ct FROM e WHERE idt = ?", [self.tag("pid", pid)])
        if not rows:
            return False
        r = self.rc.open(rows[0][0])._replace(hours=hours)
        hom = self._enc_hom(hours) if self.hom else None
        self.c.p[0].execute("UPDATE e SET hom = ?, ct = ? WHERE idt = ?", [hom, self.rc.seal(r), self.tag("pid", pid)])
        return True

    def delete(self, pid: str) -> bool:
        return self.c.p[0].execute("DELETE FROM e WHERE idt = ?", [self.tag("pid", pid)]) > 0

    def state_bytes(self) -> int:
        return 0


class EncryptedScan:
    """One provider stores AES-GCM records; every query downloads all of them."""

    name = "AEAD scan"

    def __init__(self, cluster: Cluster):
        self.rc = _RecordCipher(new_master_key())
        self.c = cluster
        self.c.p[0].script("CREATE TABLE e (ct BLOB)")

    def insert(self, recs):
        t0 = time.perf_counter()
        for off in range(0, len(recs), BATCH):
            self.c.p[0].executemany("INSERT INTO e VALUES (?)", [(self.rc.seal(r),) for r in recs[off:off + BATCH]])
        return (time.perf_counter() - t0) * 1e3

    def query(self, q: Query):
        recs = [self.rc.open(r[0]) for r in self.c.p[0].execute("SELECT ct FROM e")]
        if q.agg == "lookup":
            hit = [r for r in recs if r.pid == q.pid]
            return hit[0] if hit else None
        sel = [r.hours for r in recs if all(
            (v[0] <= r.age <= v[1]) if a == "age" else getattr(r, a) == v for a, v in q.predicates())]
        return (len(sel), None if q.agg == "count" else sum(sel))

    def _find(self, pid):
        for rowid, ct in self.c.p[0].execute("SELECT rowid, ct FROM e"):
            r = self.rc.open(ct)
            if r.pid == pid:
                return rowid, r
        return None, None

    def update(self, pid: str, hours: int) -> bool:
        rowid, r = self._find(pid)
        if r is None:
            return False
        self.c.p[0].execute("UPDATE e SET ct = ? WHERE rowid = ?", [self.rc.seal(r._replace(hours=hours)), rowid])
        return True

    def delete(self, pid: str) -> bool:
        rowid, _ = self._find(pid)
        if rowid is None:
            return False
        self.c.p[0].execute("DELETE FROM e WHERE rowid = ?", [rowid])
        return True

    def state_bytes(self) -> int:
        return 0

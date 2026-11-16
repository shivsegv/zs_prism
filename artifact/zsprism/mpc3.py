"""Three-party replicated secret sharing (RSS) baseline.

This follows the honest-majority 3PC design used by Sharemind, Secrecy and
related analytics systems: every attribute is secret-shared among three
servers so that no server sees any value; predicates are evaluated as Boolean
circuits on bit-sliced XOR shares, results are converted to arithmetic shares
over Z_{2^64}, and only the final aggregate (or the selected record) is
revealed to the proxy.

Party i holds components (x_i, x_{i+1}) of x = x_0 + x_1 + x_2 (or XOR).
Multiplication/AND: z_i = x_i y_i + x_i y_{i+1} + x_{i+1} y_i + alpha_i,
then z_i is sent to party i-1 (one round).  alpha is a zero-sharing derived
from pairwise AES-CTR keys.  Parties are separate processes connected in a
ring over TCP; every ring message is delayed by RTT/2 + bytes/rate, and every
proxy request/response by RTT + bytes/rate, matching rpc.py.
"""
from __future__ import annotations

import multiprocessing as mp
import secrets
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Sequence

import msgpack
import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .data import Query, Record
from .rpc import recv_frame, send_frame

U64 = np.uint64
ALL1 = np.uint64(0xFFFFFFFFFFFFFFFF)
CATEG = ("sex", "education", "marital", "occupation", "race", "country")


# ------------------------------------------------------------------ framing
def _send(sock, obj):
    return send_frame(sock, msgpack.packb(obj, use_bin_type=True))


def _recv(sock):
    body = recv_frame(sock)
    return msgpack.unpackb(body, raw=False), len(body) + 8


def _arr(b: bytes, shape=None):
    a = np.frombuffer(b, dtype=U64).copy()
    return a.reshape(shape) if shape else a


# ------------------------------------------------------------------ bit slicing
def bitslice(values: np.ndarray, bits: int) -> np.ndarray:
    """(N,) uint64 -> (bits, W) planes; row 64w+t is bit t of word w."""
    w = len(values) // 64
    v = values.reshape(w, 64)
    shifts = np.arange(64, dtype=U64)
    return np.stack([(((v >> U64(j)) & U64(1)) << shifts).sum(axis=1, dtype=U64) for j in range(bits)])


def unslice(plane: np.ndarray) -> np.ndarray:
    return ((plane[:, None] >> np.arange(64, dtype=U64)) & U64(1)).reshape(-1)


# ------------------------------------------------------------------ party
class _Party:
    def __init__(self, idx, keys, prev_sock, next_sock):
        self.i = idx
        self.prev, self.next = prev_sock, next_sock
        self.k_own, self.k_next = keys          # k_i (shared with i-1), k_{i+1} (shared with i+1)
        self.ctr = 0
        self.rtt = 0.0
        self.rate = 0.0
        self.rounds = 0
        self.ring_bytes = 0
        self.boolc: Dict[str, tuple] = {}
        self.arith: Dict[str, tuple] = {}
        self.n = 0

    # correlated randomness
    def _prf(self, key, nbytes):
        nonce = self.ctr.to_bytes(16, "big")
        enc = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor()
        return np.frombuffer(enc.update(b"\0" * nbytes), dtype=U64)

    def _zero(self, n, boolean):
        self.ctr += 1
        a, b = self._prf(self.k_own, 8 * n), self._prf(self.k_next, 8 * n)
        return (a ^ b) if boolean else (a - b)

    # one communication round: send own component to prev, receive from next
    def _exchange(self, z: np.ndarray) -> np.ndarray:
        payload = z.tobytes()
        delay = self.rtt / 2 + (len(payload) / self.rate if self.rate else 0.0)

        def tx():
            if delay:
                time.sleep(delay)
            send_frame(self.prev, payload)
        t = threading.Thread(target=tx)
        t.start()
        other = np.frombuffer(recv_frame(self.next), dtype=U64).copy()
        t.join()
        self.rounds += 1
        self.ring_bytes += len(payload)
        return other

    def and_(self, x, y):
        shape = x[0].shape
        xa, xb, ya, yb = (v.reshape(-1) for v in (*x, *y))
        z = (xa & ya) ^ (xa & yb) ^ (xb & ya) ^ self._zero(len(xa), True)
        return z.reshape(shape), self._exchange(z).reshape(shape)

    def mul(self, x, y):
        shape = x[0].shape
        xa, xb, ya, yb = (v.reshape(-1) for v in (*x, *y))
        z = xa * ya + xa * yb + xb * ya + self._zero(len(xa), False)
        return z.reshape(shape), self._exchange(z).reshape(shape)

    def xor_const(self, x, c: np.ndarray):
        a, b = x[0].copy(), x[1].copy()
        if self.i == 0:
            a ^= c
        if self.i == 2:
            b ^= c
        return a, b

    def and_many(self, pairs):
        """Evaluate independent ANDs in one round."""
        if not pairs:
            return []
        sizes = [p[0][0].size for p in pairs]
        shapes = [p[0][0].shape for p in pairs]
        X = (np.concatenate([p[0][0].reshape(-1) for p in pairs]), np.concatenate([p[0][1].reshape(-1) for p in pairs]))
        Y = (np.concatenate([p[1][0].reshape(-1) for p in pairs]), np.concatenate([p[1][1].reshape(-1) for p in pairs]))
        Z = self.and_(X, Y)
        out, off = [], 0
        for s, sh in zip(sizes, shapes):
            out.append((Z[0][off:off + s].reshape(sh), Z[1][off:off + s].reshape(sh)))
            off += s
        return out

    # circuits as generators yielding lists of AND pairs -------------------
    @staticmethod
    def _reduce(planes):
        """AND of all rows of a (k, W) share pair, log depth."""
        a, b = planes
        while a.shape[0] > 1:
            h = a.shape[0] // 2
            res = yield [((a[:h], b[:h]), (a[h:2 * h], b[h:2 * h]))]
            ra, rb = res[0]
            if a.shape[0] % 2:
                ra, rb = np.concatenate([ra, a[-1:]]), np.concatenate([rb, b[-1:]])
            a, b = ra, rb
        return a[0], b[0]

    def _eq(self, attr, const):
        a, b = self.boolc[attr]
        bits = a.shape[0]
        mask = np.array([0 if (const >> j) & 1 else 0xFFFFFFFFFFFFFFFF for j in range(bits)], dtype=U64)[:, None]
        x = self.xor_const((a, b), mask)          # bit j is 1 iff x_j == c_j
        return (yield from self._reduce(x))

    def _range(self, attr, lo, hi):
        a, b = self.boolc[attr]
        nb = a.shape[0]
        outs = []
        for c, want_lt in ((lo, True), (hi, False)):
            mask = np.array([0 if (c >> j) & 1 else 0xFFFFFFFFFFFFFFFF for j in range(nb)], dtype=U64)[:, None]
            outs.append((self.xor_const((a, b), mask), c, want_lt))
        # suffix products E_j = AND_{k>j} eq_k, computed by Hillis-Steele doubling (log depth)
        E = []
        for eqb, c, want_lt in outs:
            ea, eb = eqb
            sa = np.concatenate([ea[1:], np.zeros_like(ea[:1])])   # S_j = eq_{j+1}; S_{nb-1} = public 1
            sb = np.concatenate([eb[1:], np.zeros_like(eb[:1])])
            sa, sb = self.xor_const((sa, sb), np.array([0] * (nb - 1) + [0xFFFFFFFFFFFFFFFF], dtype=U64)[:, None])
            E.append([sa, sb])
        d = 1
        while d < nb:
            pairs = []
            for e in E:
                lo_i = nb - d  # rows j with j+d < nb get multiplied by row j+d
                pairs.append(((e[0][:lo_i], e[1][:lo_i]), (e[0][d:], e[1][d:])))
            res = yield pairs
            for e, (ra, rb) in zip(E, res):
                e[0] = np.concatenate([ra, e[0][nb - d:]])
                e[1] = np.concatenate([rb, e[1][nb - d:]])
            d *= 2
        # terms: lt: c_j=1 & x_j=0 & E_j ; gt: c_j=0 & x_j=1 & E_j  (mutually exclusive -> XOR)
        pairs, meta = [], []
        for (eqb, c, want_lt), e in zip(outs, E):
            for j in range(nb):
                cj = (c >> j) & 1
                if want_lt and cj == 1:
                    xj = self.xor_const((a[j], b[j]), ALL1)          # not x_j
                elif not want_lt and cj == 0:
                    xj = (a[j], b[j])
                else:
                    continue
                pairs.append((xj, (e[0][j], e[1][j])))
                meta.append(want_lt)
        res = yield pairs
        lt = [np.zeros_like(a[0]), np.zeros_like(a[0])]
        gt = [np.zeros_like(a[0]), np.zeros_like(a[0])]
        for (ra, rb), is_lt in zip(res, meta):
            tgt = lt if is_lt else gt
            tgt[0] ^= ra
            tgt[1] ^= rb
        nlt = self.xor_const(tuple(lt), ALL1)
        ngt = self.xor_const(tuple(gt), ALL1)
        r = yield [(nlt, ngt)]
        return r[0]

    def _run_parallel(self, gens):
        """Drive circuit generators level-synchronously (rounds = max depth)."""
        results = [None] * len(gens)
        pending = {}
        for k, g in enumerate(gens):
            try:
                pending[k] = (g, g.send(None))
            except StopIteration as st:
                results[k] = st.value
        while pending:
            order = list(pending)
            flat = [p for k in order for p in pending[k][1]]
            res = self.and_many(flat)
            off, nxt = 0, {}
            for k in order:
                g, req = pending[k]
                part = res[off:off + len(req)]
                off += len(req)
                try:
                    nxt[k] = (g, g.send(part))
                except StopIteration as st:
                    results[k] = st.value
            pending = nxt
        return results

    def _b2a(self, bit):
        """XOR-shared bit planes (W,) -> arithmetic shares per row (N,)."""
        comps = {self.i: unslice(bit[0])[:self.n], (self.i + 1) % 3: unslice(bit[1])[:self.n]}
        z = np.zeros(self.n, dtype=U64)

        def share_of(j):  # arithmetic RSS of the j-th XOR component (known to two parties)
            return (comps.get(self.i, z) if j == self.i else z,
                    comps.get((self.i + 1) % 3, z) if j == (self.i + 1) % 3 else z)
        a, b, c = share_of(0), share_of(1), share_of(2)
        ab = self.mul(a, b)
        t = (a[0] + b[0] - U64(2) * ab[0], a[1] + b[1] - U64(2) * ab[1])
        tc = self.mul(t, c)
        return (t[0] + c[0] - U64(2) * tc[0], t[1] + c[1] - U64(2) * tc[1])

    def query(self, preds, agg):
        gens = []
        for p in preds:
            gens.append(self._range(p[1], p[2], p[3]) if p[0] == "range" else self._eq(p[1], p[2]))
        bits = self._run_parallel(gens)
        if len(bits) > 1:
            stack = (np.stack([x[0] for x in bits]), np.stack([x[1] for x in bits]))
            sel = self._run_parallel([self._reduce(stack)])[0]
        else:
            sel = bits[0]
        s = self._b2a(sel)
        if agg == "lookup":
            cols = ["pid", "age", *CATEG, "hours"]
            X = (np.concatenate([np.tile(s[0], 1)] * len(cols)), np.concatenate([np.tile(s[1], 1)] * len(cols)))
            Y = (np.concatenate([self.arith[c][0] for c in cols]), np.concatenate([self.arith[c][1] for c in cols]))
            prod = self.mul(X, Y)
            sums = [[int(prod[0][k * self.n:(k + 1) * self.n].sum(dtype=U64)),
                     int(prod[1][k * self.n:(k + 1) * self.n].sum(dtype=U64))] for k in range(len(cols))]
            return {"cols": cols, "sums": sums, "count": [int(s[0].sum(dtype=U64)), int(s[1].sum(dtype=U64))]}
        out = {"count": [int(s[0].sum(dtype=U64)), int(s[1].sum(dtype=U64))]}
        if agg == "avg":
            prod = self.mul(s, self.arith["hours"])
            out["sum"] = [int(prod[0].sum(dtype=U64)), int(prod[1].sum(dtype=U64))]
        return out


def _party_main(idx, conn):
    lst = socket.socket()
    lst.bind(("127.0.0.1", 0))
    lst.listen(4)
    ring = socket.socket()
    ring.bind(("127.0.0.1", 0))
    ring.listen(1)
    conn.send((lst.getsockname()[1], ring.getsockname()[1]))
    next_ring_port, keys = conn.recv()
    nxt = socket.create_connection(("127.0.0.1", next_ring_port))
    prv, _ = ring.accept()
    for s in (nxt, prv):
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    party = _Party(idx, keys, prv, nxt)
    proxy, _ = lst.accept()
    proxy.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    while True:
        try:
            req, nin = _recv(proxy)
        except ConnectionError:
            return
        op = req["op"]
        try:
            if op == "load":
                party.n = req["n"]
                w = req["w"]
                for col, (a, b) in req["bool"].items():
                    nb = req["bits"][col]
                    party.boolc[col] = (_arr(a, (nb, w)), _arr(b, (nb, w)))
                for col, (a, b) in req["arith"].items():
                    party.arith[col] = (_arr(a), _arr(b))
                res = {"ok": True}
            elif op == "net":
                party.rtt, party.rate = req["rtt_ms"] / 1e3, req["bw_mbps"] * 1e6 / 8
                res = {"ok": True}
            elif op == "query":
                party.rounds = party.ring_bytes = 0
                r = party.query(req["preds"], req["agg"])
                res = {"ok": True, "r": r, "rounds": party.rounds, "ring_bytes": party.ring_bytes}
            elif op == "size":
                res = {"ok": True, "r": sum(a.nbytes + b.nbytes for a, b in (*party.boolc.values(), *party.arith.values()))}
            else:
                raise ValueError(op)
        except Exception as exc:  # pragma: no cover
            res = {"ok": False, "e": repr(exc)}
        body = msgpack.packb(res, use_bin_type=True)
        if op == "query":      # proxy hop: RTT plus transfer, after processing (as in rpc.py)
            time.sleep(party.rtt + ((nin + len(body)) / party.rate if party.rate else 0.0))
        send_frame(proxy, body)


# ------------------------------------------------------------------ proxy side
class _Conn:
    def __init__(self, port):
        self.sock = socket.create_connection(("127.0.0.1", port))
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.bytes = 0

    def call(self, **req):
        self.bytes += _send(self.sock, req)
        res, n = _recv(self.sock)
        self.bytes += n
        if not res["ok"]:
            raise RuntimeError(res["e"])
        return res


class MPC3:
    """Proxy for the 3PC-RSS baseline (exposes the same interface as SplitSystem)."""

    name = "3PC-RSS"

    def __init__(self):
        ctx = mp.get_context("spawn")
        self.procs, pipes = [], []
        for i in range(3):
            a, b = ctx.Pipe()
            p = ctx.Process(target=_party_main, args=(i, b), daemon=True)
            p.start()
            self.procs.append(p)
            pipes.append(a)
        ports = [p.recv() for p in pipes]
        keys = [secrets.token_bytes(16) for _ in range(3)]
        for i, p in enumerate(pipes):
            p.send((ports[(i + 1) % 3][1], (keys[i], keys[(i + 1) % 3])))
        self.c = [_Conn(ports[i][0]) for i in range(3)]
        self.pool = ThreadPoolExecutor(3)
        self.codes: Dict[str, Dict[str, int]] = {}
        self.last_rounds = 0
        self.last_ring_bytes = 0

    # data are loaded once (bulk); dictionaries for categorical codes are schema metadata
    def insert(self, recs: Sequence[Record]) -> float:
        t0 = time.perf_counter()
        n = len(recs)
        npad = -(-n // 64) * 64
        self.n = n
        self.bits = {"pid": 32, "age": 7}
        for a in CATEG:
            dom = sorted({getattr(r, a) for r in recs})
            self.codes[a] = {v: i for i, v in enumerate(dom)}
            self.bits[a] = max(1, (len(dom) - 1).bit_length())
        self.decode = {a: {i: v for v, i in m.items()} for a, m in self.codes.items()}
        if max(r.age for r in recs) >= 128:
            raise ValueError("age exceeds 7 bits")
        cols = {"pid": np.array([int(r.pid[1:]) for r in recs], dtype=U64),
                "age": np.array([r.age for r in recs], dtype=U64),
                "hours": np.array([r.hours for r in recs], dtype=U64)}
        for a in CATEG:
            cols[a] = np.array([self.codes[a][getattr(r, a)] for r in recs], dtype=U64)
        bool_sh = [dict() for _ in range(3)]
        ar_sh = [dict() for _ in range(3)]
        for name, v in cols.items():
            vp = np.zeros(npad, dtype=U64)
            vp[:n] = v
            r0 = np.frombuffer(secrets.token_bytes(8 * n), dtype=U64)
            r1 = np.frombuffer(secrets.token_bytes(8 * n), dtype=U64)
            comp = [r0, r1, v - r0 - r1]
            for i in range(3):
                ar_sh[i][name] = (comp[i].tobytes(), comp[(i + 1) % 3].tobytes())
            if name in self.bits:
                planes = bitslice(vp, self.bits[name])
                b0 = np.frombuffer(secrets.token_bytes(planes.nbytes), dtype=U64).reshape(planes.shape)
                b1 = np.frombuffer(secrets.token_bytes(planes.nbytes), dtype=U64).reshape(planes.shape)
                bc = [b0, b1, planes ^ b0 ^ b1]
                for i in range(3):
                    bool_sh[i][name] = (bc[i].tobytes(), bc[(i + 1) % 3].tobytes())
        list(self.pool.map(lambda i: self.c[i].call(op="load", n=n, w=npad // 64, bits=self.bits,
                                                    bool=bool_sh[i], arith=ar_sh[i]), range(3)))
        return (time.perf_counter() - t0) * 1e3

    def set_network(self, rtt_ms, bw_mbps):
        for c in self.c:
            c.call(op="net", rtt_ms=rtt_ms, bw_mbps=bw_mbps)

    def _open(self, comps):
        """Reconstruct x0+x1+x2 from the (x_i, x_{i+1}) pairs of all three parties."""
        x = [comps[0][0], comps[1][0], comps[2][0]]
        if comps[0][1] != x[1] or comps[1][1] != x[2] or comps[2][1] != x[0]:
            raise RuntimeError("inconsistent shares (party misbehaviour)")
        return sum(x) % (1 << 64)

    def query(self, q: Query):
        preds = []
        if q.agg == "lookup":
            preds.append(["eq", "pid", int(q.pid[1:])])
        for a, v in q.predicates():
            if a == "age":
                preds.append(["range", "age", int(v[0]), int(v[1])])
            else:
                code = self.codes[a].get(v)
                if code is None:
                    return (0, None if q.agg == "count" else 0)
                preds.append(["eq", a, code])
        res = list(self.pool.map(lambda i: self.c[i].call(op="query", preds=preds, agg=q.agg), range(3)))
        self.last_rounds = res[0]["rounds"]
        self.last_ring_bytes = sum(r["ring_bytes"] for r in res)
        rs = [r["r"] for r in res]
        count = self._open([r["count"] for r in rs])
        if q.agg == "lookup":
            if count == 0:
                return None
            vals = {c: self._open([r["sums"][k] for r in rs]) for k, c in enumerate(rs[0]["cols"])}
            kw = {a: self.decode[a][vals[a]] for a in CATEG}
            return Record(q.pid, vals["age"], kw["sex"], kw["education"], kw["marital"],
                          kw["occupation"], kw["race"], kw["country"], vals["hours"])
        if q.agg == "count":
            return (count, None)
        return (count, self._open([r["sum"] for r in rs]))

    def state_bytes(self):
        return 0

    def close(self):
        for c in self.c:
            c.sock.close()
        for p in self.procs:
            p.terminate()
        self.pool.shutdown(wait=False)

"""Storage-provider service and proxy-side client.

Each provider is a separate OS process that owns one SQLite database and
exposes a minimal SQL endpoint over TCP (length-prefixed MessagePack frames),
as a database-as-a-service front end would.  Wide-area conditions are
emulated at the provider by delaying every response by the configured
round-trip time plus the serialisation time of request and response bytes at
the configured link rate.  The proxy therefore observes real serialisation,
socket, and SQLite costs plus controlled network delay.
"""
from __future__ import annotations

import errno
import multiprocessing as mp
import socket
import socketserver
import struct
import threading
import time
import zlib
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Sequence

import msgpack
import numpy as np

# Frame = 4-byte length + 4-byte CRC-32 of the body, then the body.
_HDR = struct.Struct(">II")
_CHUNK = 1 << 18


class FrameError(ConnectionError):
    """A frame failed its integrity check."""


def send_frame(sock: socket.socket, body: bytes) -> int:
    """Send one checksummed frame in bounded chunks.

    Large single send() calls on the macOS loopback interface can fail
    transiently with ENOBUFS; writing at most 256 KiB per call and retrying
    that error after a short back-off keeps large frames reliable, and the
    CRC lets the receiver reject any frame that arrives damaged.
    """
    view = memoryview(_HDR.pack(len(body), zlib.crc32(body)) + body)
    sent = retries = 0
    while sent < len(view):
        try:
            sent += sock.send(view[sent:sent + _CHUNK])
            retries = 0
        except OSError as exc:
            if exc.errno not in (errno.ENOBUFS, errno.EAGAIN) or retries >= 1000:
                raise
            retries += 1
            time.sleep(0.001)
    return len(view)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(min(1 << 20, n - len(buf)))
        if not chunk:
            raise ConnectionError("peer closed")
        buf += chunk
    return bytes(buf)


def recv_frame(sock: socket.socket) -> bytes:
    n, crc = _HDR.unpack(_recv_exact(sock, _HDR.size))
    body = _recv_exact(sock, n)
    if zlib.crc32(body) != crc:
        raise FrameError("frame failed CRC-32 check")
    return body


def _send(sock: socket.socket, obj: Any) -> int:
    return send_frame(sock, msgpack.packb(obj, use_bin_type=True))


def _recv(sock: socket.socket):
    body = recv_frame(sock)
    return msgpack.unpackb(body, raw=False), len(body) + _HDR.size


# --------------------------------------------------------------------------
# Provider side
# --------------------------------------------------------------------------
class _ModSum:
    """SUM over Z_q evaluated inside the provider (shares stay uniform)."""

    def __init__(self):
        self.acc = 0
        self.q = None

    def step(self, value, q):
        self.q = q
        self.acc = (self.acc + value) % q

    def finalize(self):
        return self.acc


class _PaillierSum:
    """Homomorphic addition: product of Paillier ciphertexts modulo n^2."""

    def __init__(self):
        self.acc = None
        self.n2 = None

    def step(self, ct: bytes, n2: bytes):
        if self.n2 is None:
            self.n2 = int.from_bytes(n2, "big")
            self.acc = 1
        self.acc = (self.acc * int.from_bytes(ct, "big")) % self.n2

    def finalize(self):
        if self.acc is None:
            return None
        return self.acc.to_bytes((self.acc.bit_length() + 7) // 8 or 1, "big")


def _serve(conn_pipe, name: str):
    import sqlite3

    try:
        import gmpy2  # noqa: F401  (optional acceleration of big-int products)

        class _FastPaillierSum(_PaillierSum):
            def step(self, ct, n2):
                if self.n2 is None:
                    self.n2 = gmpy2.mpz(int.from_bytes(n2, "big"))
                    self.acc = gmpy2.mpz(1)
                self.acc = gmpy2.f_mod(self.acc * gmpy2.mpz(int.from_bytes(ct, "big")), self.n2)

            def finalize(self):
                if self.acc is None:
                    return None
                v = int(self.acc)
                return v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
        paillier_cls = _FastPaillierSum
    except ImportError:  # pragma: no cover
        paillier_cls = _PaillierSum

    db = sqlite3.connect(":memory:", check_same_thread=False, isolation_level=None)
    # Keep temporary (semi-join) tables in memory and give the B-trees a
    # 256 MiB page cache; identical for every provider and every system.
    db.execute("PRAGMA temp_store = MEMORY")
    db.execute("PRAGMA cache_size = -262144")
    db.create_aggregate("zs_modsum", 2, _ModSum)
    db.create_aggregate("paillier_sum", 2, paillier_cls)
    lock = threading.Lock()
    net = {"rtt": 0.0, "bw": 0.0}

    def handle(req: Dict[str, Any]):
        op = req["op"]
        if op == "exec":
            cur = db.executemany(req["sql"], req["p"]) if req.get("many") else db.execute(req["sql"], req.get("p", ()))
            return cur.fetchall() if cur.description else cur.rowcount
        if op in ("cols", "probe_cols"):
            # Packed columnar result: BLOB columns concatenated, INTEGER
            # columns as little-endian int64 arrays.  Candidate handles
            # arrive as one concatenated blob of 16-byte values.
            sql, params = req["sql"], list(req.get("p", ()))
            if req.get("cand") is not None:
                # Candidates are sliced out of the packed blob inside SQLite
                # (recursive CTE), so the semi-join runs entirely in C.
                c = req["cand"]
                sql = ("WITH RECURSIVE _i(x) AS (SELECT 0 UNION ALL SELECT x + 1 FROM _i WHERE x + 1 < ?), "
                       "_cand(k) AS (SELECT substr(?, x * 16 + 1, 16) FROM _i) " + sql)
                params = [len(c) // 16, c] + params
            if op == "probe_cols":
                cnt = db.execute(req["csql"], req["cp"]).fetchone()[0]
                if cnt > req["limit"]:
                    return [cnt, None]
            rows = db.execute(sql, params).fetchall()
            ncol = len(rows[0]) if rows else req.get("ncol", 1)
            packed = []
            for j in range(ncol):
                if rows and isinstance(rows[0][j], bytes):
                    packed.append(b"".join(r[j] for r in rows))
                else:
                    packed.append(np.fromiter((r[j] for r in rows), dtype="<i8", count=len(rows)).tobytes())
            return [len(rows), packed] if op == "probe_cols" else {"n": len(rows), "c": packed}
        if op == "script":
            db.executescript(req["sql"])
            return None
        if op == "net":
            net["rtt"] = req["rtt_ms"] / 1000.0
            net["bw"] = req["bw_mbps"] * 1e6 / 8.0
            return None
        if op == "size":
            pc = db.execute("PRAGMA page_count").fetchone()[0]
            ps = db.execute("PRAGMA page_size").fetchone()[0]
            return pc * ps
        if op == "dump":
            return db.execute(req["sql"]).fetchall()
        raise ValueError(f"unknown op {op}")

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            sock = self.request
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            while True:
                try:
                    req, nin = _recv(sock)
                except ConnectionError:
                    return
                try:
                    with lock:
                        res = {"ok": True, "r": handle(req)}
                except Exception as exc:  # report provider-side errors to proxy
                    res = {"ok": False, "e": repr(exc)}
                body = msgpack.packb(res, use_bin_type=True)
                delay = net["rtt"]
                if net["bw"]:
                    delay += (nin + len(body) + _HDR.size) / net["bw"]
                if delay > 0:          # network time is added to processing time
                    time.sleep(delay)
                send_frame(sock, body)

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True
        allow_reuse_address = True

    srv = Server(("127.0.0.1", 0), Handler)
    conn_pipe.send(srv.server_address[1])
    conn_pipe.close()
    srv.serve_forever()


class Provider:
    """Handle to one provider process."""

    def __init__(self, name: str):
        ctx = mp.get_context("spawn")
        parent, child = ctx.Pipe()
        self.name = name
        self.proc = ctx.Process(target=_serve, args=(child, name), daemon=True)
        self.proc.start()
        self.port = parent.recv()
        self.sock = socket.create_connection(("127.0.0.1", self.port))
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._lock = threading.Lock()
        self.bytes_out = 0
        self.bytes_in = 0
        self.requests = 0

    def call(self, **req):
        with self._lock:
            self.bytes_out += _send(self.sock, req)
            res, n = _recv(self.sock)
            self.bytes_in += n
            self.requests += 1
        if not res["ok"]:
            raise RuntimeError(f"{self.name}: {res['e']}")
        return res["r"]

    # convenience wrappers -------------------------------------------------
    def execute(self, sql: str, params: Sequence = ()):
        return self.call(op="exec", sql=sql, p=list(params))

    def executemany(self, sql: str, rows: List[Sequence]):
        return self.call(op="exec", sql=sql, p=[list(r) for r in rows], many=True)

    def cols(self, sql: str, params: Sequence = (), cand: Optional[bytes] = None, ncol: int = 1):
        return self.call(op="cols", sql=sql, p=list(params), cand=cand, ncol=ncol)

    def probe_cols(self, csql: str, cp, sql: str, params, limit: int, ncol: int = 1):
        return self.call(op="probe_cols", csql=csql, cp=list(cp), sql=sql, p=list(params),
                         limit=int(limit), ncol=ncol, cand=None)

    def script(self, sql: str):
        return self.call(op="script", sql=sql)

    def set_network(self, rtt_ms: float, bw_mbps: float):
        return self.call(op="net", rtt_ms=rtt_ms, bw_mbps=bw_mbps)

    def size(self) -> int:
        return self.call(op="size")

    def dump(self, sql: str):
        return self.call(op="dump", sql=sql)

    def reset_counters(self):
        self.bytes_out = self.bytes_in = self.requests = 0

    def close(self):
        try:
            self.sock.close()
        finally:
            self.proc.terminate()
            self.proc.join(timeout=2)


class Cluster:
    """A set of providers plus a thread pool for concurrent requests."""

    def __init__(self, n: int, prefix: str = "store"):
        self.p = [Provider(f"{prefix}{i}") for i in range(n)]
        self.pool = ThreadPoolExecutor(max_workers=max(4, n))

    def parallel(self, calls):
        """Run [(provider_index, fn_name, args...)] concurrently."""
        futs = [self.pool.submit(getattr(self.p[i], fn), *args) for i, fn, *args in calls]
        return [f.result() for f in futs]

    def set_network(self, rtt_ms: float, bw_mbps: float):
        for p in self.p:
            p.set_network(rtt_ms, bw_mbps)

    def reset_counters(self):
        for p in self.p:
            p.reset_counters()

    def traffic(self):
        return {
            "requests": sum(p.requests for p in self.p),
            "bytes": sum(p.bytes_in + p.bytes_out for p in self.p),
        }

    def close(self):
        for p in self.p:
            p.close()
        self.pool.shutdown(wait=False)

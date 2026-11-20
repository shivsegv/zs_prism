"""Differential correctness tests: every system vs. a plaintext reference.

Run:  python -m unittest discover -s tests -v
"""
from __future__ import annotations

import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from zsprism.crypto import KeyRing, Q, new_master_key, new_rids, share  # noqa: E402
from zsprism.data import Query, random_queries, reference, scaled  # noqa: E402
from zsprism.mpc3 import MPC3  # noqa: E402
from zsprism.rpc import Cluster  # noqa: E402
from zsprism.systems import CryptDBStyle, EncryptedScan, MapLinkage, SplitSystem  # noqa: E402


class PrimitiveTests(unittest.TestCase):
    def test_handle_roundtrip_and_store_binding(self):
        codec = KeyRing(new_master_key()).handles
        rids = new_rids(1000)
        for s in range(3):
            hs = codec.handles(rids, s)
            self.assertEqual(len(set(hs)), len(hs))
            self.assertEqual(codec.rids(hs, s), rids)
        with self.assertRaises(ValueError):
            codec.rids(codec.handles(rids[:1], 0), 1)
        # Handles of the same row at different stores are distinct.
        self.assertTrue(all(a != b for a, b in zip(codec.handles(rids, 0), codec.handles(rids, 1))))

    def test_shares(self):
        vals = [0, 1, 99, Q - 1]
        s0, s1 = share(vals)
        self.assertEqual([(a + b) % Q for a, b in zip(s0, s1)], vals)

    def test_large_frame(self):
        """64 MiB frames survive the transport (chunked send, ENOBUFS retry)."""
        import socket
        import threading
        from zsprism.rpc import FrameError, recv_frame, send_frame
        a, b = socket.socketpair()
        payload = bytes(range(256)) * (1 << 18)
        t = threading.Thread(target=send_frame, args=(a, payload))
        t.start()
        got = recv_frame(b)
        t.join()
        # A damaged frame is rejected, not mis-parsed.
        import struct
        import zlib
        a.sendall(struct.pack(">II", 3, zlib.crc32(b"abc") ^ 1) + b"abc")
        with self.assertRaises(FrameError):
            recv_frame(b)
        a.close()
        b.close()
        self.assertEqual(got, payload)

    def test_map_snapshot_roundtrip(self):
        m = MapLinkage()
        rids = new_rids(50)
        for s in range(3):
            m.assign(rids, s)
        r = MapLinkage.restore(m.snapshot())
        self.assertEqual(r.fwd, m.fwd)
        self.assertEqual(len(m.snapshot()), m.state_bytes())


def matches(r, q) -> bool:
    """Plaintext predicate evaluation, as in data.reference."""
    for a, v in q.predicates():
        x = getattr(r, a)
        if not (v[0] <= x <= v[1] if a == "age" else x == v):
            return False
    return True


class DifferentialTests(unittest.TestCase):
    N = 4000
    M = 1000

    def _exercise(self, make, n_stores, n=None, m=None):
        n = n or self.N
        m = m or self.M
        rng = random.Random(7)
        recs = scaled(n, seed=11)
        truth = list(recs)
        cl = Cluster(n_stores)
        try:
            sys_ = make(cl)
            sys_.insert(recs)
            # Split systems expose the selected row set, so we can check it directly.
            rowlevel = isinstance(sys_, SplitSystem)
            rid_of = {r.pid: sys_._lookup_rid(r.pid) for r in recs} if rowlevel else {}
            qs = random_queries(recs, m, seed=3)
            for i, q in enumerate(qs):
                if i % 25 == 0:  # interleave writes; each must be visible immediately (freshness)
                    victim = rng.choice(truth)
                    newv = rng.randint(1, 99)
                    self.assertTrue(sys_.update(victim.pid, newv))
                    truth[truth.index(victim)] = victim._replace(hours=newv)
                    self.assertEqual(sys_.query(Query("lookup", pid=victim.pid)).hours, newv)
                    gone = rng.choice(truth)
                    self.assertTrue(sys_.delete(gone.pid))
                    truth.remove(gone)
                    rid_of.pop(gone.pid, None)
                    self.assertIsNone(sys_.query(Query("lookup", pid=gone.pid)))
                    self.assertFalse(sys_.update(gone.pid, newv))
                    fresh = scaled(n, seed=1000 + i)[0]._replace(pid=f"N{i:06d}")
                    sys_.insert([fresh])
                    truth.append(fresh)
                    self.assertEqual(sys_.query(Query("lookup", pid=fresh.pid)), fresh)
                    if rowlevel:
                        rid_of[fresh.pid] = sys_._lookup_rid(fresh.pid)
                self.assertEqual(sys_.query(q), reference(truth, q), msg=f"{q}")
                if rowlevel and sys_.last_rids is not None:
                    got = {x.tobytes() for x in sys_.last_rids}
                    want = {rid_of[r.pid] for r in truth if matches(r, q)}
                    self.assertLessEqual(got, want, msg=f"soundness: extra rows for {q}")
                    self.assertLessEqual(want, got, msg=f"completeness: missing rows for {q}")
            for r in rng.sample(truth, 20):
                self.assertEqual(sys_.query(Query("lookup", pid=r.pid)), r)
        finally:
            cl.close()

    def test_zs_prism_auto(self):
        self._exercise(lambda c: SplitSystem("prp", c, plan="auto"), 3)

    def test_zs_prism_pushdown(self):
        self._exercise(lambda c: SplitSystem("prp", c, plan="pushdown"), 3)

    def test_zs_prism_broadcast(self):
        self._exercise(lambda c: SplitSystem("prp", c, plan="broadcast"), 3)

    def test_rowset_check_detects_a_missing_row(self):
        """Mutation check: a proxy that drops one selected row must fail the row-set comparison."""
        class Faulty(SplitSystem):
            def query(self, q):
                out = super().query(q)
                if self.last_rids is not None and len(self.last_rids) > 1:
                    self.last_rids = self.last_rids[1:]
                return out
        with self.assertRaisesRegex(AssertionError, "completeness"):
            self._exercise(lambda c: Faulty("prp", c, plan="auto"), 3, n=1000, m=200)

    def test_map_split(self):
        self._exercise(lambda c: SplitSystem("map", c), 3)

    def test_shared_split(self):
        self._exercise(lambda c: SplitSystem("shared", c), 3)

    def test_det_aead(self):
        self._exercise(lambda c: CryptDBStyle(c, hom=False), 1)

    def test_det_paillier(self):
        self._exercise(lambda c: CryptDBStyle(c, hom=True, paillier_bits=1024), 1, n=600, m=300)

    def test_mpc3(self):
        """3PC-RSS is bulk-loaded; queries and lookups only (no writes)."""
        recs = scaled(3000, seed=11)
        m = MPC3()
        try:
            m.insert(recs)
            for q in random_queries(recs, 300, seed=3):
                self.assertEqual(m.query(q), reference(recs, q), msg=f"{q}")
            for r in random.Random(2).sample(recs, 20):
                self.assertEqual(m.query(Query("lookup", pid=r.pid)), r)
        finally:
            m.close()

    def test_scan(self):
        self._exercise(lambda c: EncryptedScan(c), 1, n=1500, m=300)


if __name__ == "__main__":
    unittest.main()

"""UCI Adult loader and workload generator."""
from __future__ import annotations

import random
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional, Tuple

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


class Record(NamedTuple):
    pid: str          # surrogate direct identifier (Adult has none)
    age: int
    sex: str
    education: str
    marital: str
    occupation: str   # sensitive attribute
    race: str
    country: str
    hours: int        # numeric measure (hours-per-week)


def load_adult() -> List[Record]:
    """Adult train+test with missing values removed (45,222 records)."""
    out: List[Record] = []
    for fname in ("adult.data", "adult.test"):
        for line in (DATA_DIR / fname).read_text().splitlines():
            parts = [p.strip() for p in line.split(",")]
            if len(parts) != 15 or "?" in parts:
                continue
            age, _, _, edu, _, mar, occ, _, race, sex, _, _, hours, cty, _ = parts
            out.append(Record("", int(age), sex, edu, mar, occ, race, cty, int(hours)))
    return [r._replace(pid=f"P{i:09d}") for i, r in enumerate(out)]


def load_census() -> List[Record]:
    """UCI Census-Income (KDD), train+test (299,285 records).

    Mapping: age, sex, education, marital status, major occupation code,
    race, country of birth (self); measure = weeks worked in year.
    Values are taken verbatim; '?' entries stay as their own category.
    """
    out: List[Record] = []
    for fname in ("census-income.data", "census-income.test"):
        for line in (DATA_DIR / "census" / fname).read_text().splitlines():
            f = [x.strip() for x in line.split(",")]
            if len(f) != 42:
                continue
            out.append(Record("", int(f[0]), f[12], f[4], f[7], f[9], f[10], f[34], int(f[39])))
    return [r._replace(pid=f"C{i:09d}") for i, r in enumerate(out)]


def scaled(n: int, seed: int) -> List[Record]:
    """Adult itself for n == len(Adult); otherwise sample with replacement."""
    base = load_adult()
    if n == len(base):
        return base
    rng = random.Random(seed)
    return [rng.choice(base)._replace(pid=f"P{i:09d}") for i in range(n)]


ATTR_STORE: Dict[str, int] = {
    "age": 0, "sex": 0,
    "education": 1, "marital": 1,
    "occupation": 2, "race": 2, "country": 2,
}


class Query(NamedTuple):
    agg: str                                   # "count" | "avg" | "lookup"
    age: Optional[Tuple[int, int]] = None
    sex: Optional[str] = None
    education: Optional[str] = None
    marital: Optional[str] = None
    occupation: Optional[str] = None
    race: Optional[str] = None
    country: Optional[str] = None
    pid: Optional[str] = None

    def predicates(self):
        for a in ATTR_STORE:
            v = getattr(self, a)
            if v is not None:
                yield a, v


# Named workloads used throughout the evaluation.
WORKLOADS = {
    "Q1 lookup": None,  # filled per dataset (pid of a sampled record)
    "Q2 count-1": Query("count", occupation="Prof-specialty"),
    "Q3 range-avg": Query("avg", age=(30, 45)),
    "Q4 conj-avg": Query("avg", age=(30, 45), education="Bachelors", occupation="Exec-managerial"),
    "Q5 conj-sel": Query("avg", age=(70, 75), sex="Female", marital="Widowed", country="United-States"),
}


def random_queries(records: List[Record], m: int, seed: int) -> List[Query]:
    """Random conjunctive COUNT/AVG queries over 1-4 attributes."""
    rng = random.Random(seed)
    domains = {a: sorted({getattr(r, a) for r in records}) for a in ATTR_STORE if a != "age"}
    out = []
    for _ in range(m):
        k = rng.randint(1, 4)
        attrs = rng.sample(list(ATTR_STORE), k)
        kw = {}
        for a in attrs:
            if a == "age":
                lo = rng.randint(17, 80)
                kw["age"] = (lo, lo + rng.randint(0, 20))
            else:
                kw[a] = rng.choice(domains[a])
        out.append(Query(rng.choice(["count", "avg"]), **kw))
    return out


def reference(records: List[Record], q: Query):
    """Plaintext ground truth."""
    if q.agg == "lookup":
        hit = [r for r in records if r.pid == q.pid]
        return hit[0] if hit else None
    sel = []
    for r in records:
        ok = True
        for a, v in q.predicates():
            x = getattr(r, a)
            if a == "age":
                ok = v[0] <= x <= v[1]
            else:
                ok = x == v
            if not ok:
                break
        if ok:
            sel.append(r.hours)
    if q.agg == "count":
        return (len(sel), None)
    return (len(sel), sum(sel))


CENSUS_WORKLOADS = {
    "Q2 count-1": Query("count", occupation="Professional specialty"),
    "Q3 range-avg": Query("avg", age=(30, 45)),
    "Q4 conj-avg": Query("avg", age=(30, 45), education="Bachelors degree(BA AB BS)",
                         occupation="Executive admin and managerial"),
    "Q5 conj-sel": Query("avg", age=(70, 75), sex="Female", marital="Widowed", country="United-States"),
}

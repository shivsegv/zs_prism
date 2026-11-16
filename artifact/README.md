# ZS-PRISM artifact

Code, data pointers, and scripts that regenerate every number, table, and
data figure in *ZS-PRISM: Stateless and Unlinkable Record Linkage for
Privacy-Preserving Multi-Cloud Data Splitting*.

## Layout

| Path | Contents |
|---|---|
| `zsprism/crypto.py` | HKDF key hierarchy, AES-256 PRP handle codec, HMAC tokens, additive shares |
| `zsprism/rpc.py` | Provider service (one process per provider, SQLite, MessagePack over TCP) with RTT/bandwidth emulation; proxy client |
| `zsprism/systems.py` | ZS-PRISM proxy and adaptive executor; Map split, Shared-TID split, DET+Paillier, DET+AEAD, AEAD scan baselines |
| `zsprism/mpc3.py` | Three-party replicated-secret-sharing baseline (Boolean circuits, B2A, real ring rounds between 3 processes) |
| `zsprism/anonymize.py` | MDAV microaggregation and Mondrian k-anonymity |
| `zsprism/data.py` | UCI Adult and Census-Income loaders, workloads, plaintext reference |
| `tests/test_correctness.py` | Primitive tests and differential tests of every system against the plaintext reference |
| `experiments/e1_local.py` … `e6_writes.py` | Experiments E1–E6 (see table below) |
| `experiments/make_figures.py`, `make_tables.py` | Figures (`figures/*.pdf`) and every number in the paper (`../paper/generated/*.tex`) |
| `results/*.json` | Raw measurements, including host and library versions (`env`) |

| Experiment | Paper | Script | Approx. runtime (Apple M4) |
|---|---|---|---|
| Correctness (all systems) | §VI-A | `python -m unittest discover -s tests` | 1 min |
| Proxy state and replica bootstrap (C1) | §VI-B, Fig. 3 | `e3_state.py` | 3 min |
| Local performance, 45k–1M records | §VI-C, Table IV | `e1_local.py` | 60 min |
| Selectivity ordering and WAN emulation (C3) | §VI-D, Fig. 4 | `e2_wan.py` | 30 min |
| Second data set (Census-Income, 299k) | §VI-E, Table V | `e7_census.py` | 25 min |
| Matched settings of recent systems (SCQL WAN, S² intra-region), 10⁶ records | §VI-F, Table VI | `e8_sota_settings.py` | 20 min |
| Writes with dual-share refresh (C2) | §VI-G | `e6_writes.py` | 5 min |
| Snapshot collusion attacks | §VI-H | `e4_linkage.py` | 5 min |
| Query-trace intersection attack | §VI-H, Fig. 5 | `e4_trace.py` | 5 min |
| Anonymization utility (MDAV, Mondrian) | baseline data; plot in `figures/utility.pdf` | `e5_anon.py` | 3 min |

## Reproduce

```sh
python3.12 -m venv .venv && . .venv/bin/activate     # Python >= 3.9; results use 3.12
pip install -r requirements.txt
./run_all.sh            # tests, all experiments, figures, numbers, PDF (~3 h on an Apple M4)
```

`run_all.sh` downloads UCI Adult (doi:10.24432/C5XW20) and Census-Income
(KDD) into `data/` if they are absent, then writes every raw measurement to
`results/*.json` (each file records host, OS, Python, SQLite, and library
versions under `env`) and its console output to `results/run_all.log`.
The shipped `results/` directory is the output of one such run (`results/run_all.log`, E8 in `results/e8_sota_settings.log`); `scql_*.json` come from `scql_bench/run_scql.py`, which needs Docker and is run separately (see below).

To check the implementation without the benchmarks:

```sh
python -m unittest discover -s tests -v          # 13 tests, about 1 min
```

The differential tests compare every system against a plaintext reference
on randomized queries interleaved with inserts, updates, and deletes.

Keys are drawn fresh from the OS CSPRNG on every run; no fixed keys or seeds
touch the cryptography. Data sampling and workload generation use fixed seeds,
so query answers are deterministic, while latencies vary with the host.

## Scope

Providers are separate local processes; wide-area conditions are emulated by
delaying each response by the configured RTT plus the transfer time of
request and response bytes at the configured link rate. The prototype is not
hardened for production: it has no TLS between proxy and providers, no
cross-provider atomic commit, and no key rotation tooling.

## SecretFlow-SCQL comparison (§VI-F, Table VI)

`scql_bench/` measures the released SCQL system on the same records and
queries. It needs Docker (≥ 8 GB for the VM) and Go ≥ 1.22.

```sh
cd scql_bench
./build_tools.sh                 # builds scdbclient and scqltool from SCQL tag 1.0.0b1
python run_scql.py --n 45222     # Adult; writes ../results/scql_45222.json
python run_scql.py --n 1000000 --reps 3
```

* Image `secretflow/scql:1.0.0b1` (latest published release); deployment
  copied from SCQL's `examples/scdb-tutorial` (Apache-2.0, see
  `deploy/LICENSE.scql`). Only change: SCDB timeouts raised (engine 900 s,
  result callback 15 min) so that 10⁶-record queries can finish.
* Parties: alice holds `(id, age, sex, hours)`, bob the other attributes.
  CCL as in the tutorial: own columns in plaintext; peer sees join keys after
  the join, comparison outcomes, and aggregates.
* WAN: `tc netem` (10 ms each way, 100 Mb/s) via a `nicolaka/netshoot`
  sidecar, filtered to engine-to-engine traffic only; the measured RTT is
  stored with the results.
* Every answer is checked against the plaintext reference; latency is the
  duration reported by `scdbclient` for each query (median of 5 runs after a
  warm-up; 3 runs at 10⁶ records).

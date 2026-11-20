# ZS-PRISM

Stateless and unlinkable record linkage for privacy-preserving multi-cloud data splitting.

This repository holds the paper and the code that produced every number, table and figure in it.

* Paper: [`paper/main.pdf`](paper/main.pdf), LaTeX source in `paper/`
* Implementation, tests, experiments and raw results: `artifact/` (details in [`artifact/README.md`](artifact/README.md))

## Contributions

1. **Stateless root-key linkage.** Row handles are derived from a 32-byte root key, so the proxy keeps no per-record map.
2. **Dual-share splitting with refresh.** Measures are stored as two additive shares that are both re-randomized on update.
3. **Selectivity-ordered conjunctive execution.** Predicates run in order of estimated selectivity, with an adaptive probe for wide-area links.

## Layout

| Path | Contents |
|---|---|
| `paper/` | `main.tex`, `refs.bib`, TikZ figures, generated numbers and tables, IEEEtran class |
| `artifact/zsprism/` | Handle codec, provider service, ZS-PRISM proxy and baselines, 3-party secret sharing, MDAV/Mondrian |
| `artifact/tests/` | Primitive tests and differential tests against a plaintext reference |
| `artifact/experiments/` | One script per experiment, plus figure and table generation |
| `artifact/results/` | Raw measurements (JSON, with host and library versions) and run logs |
| `artifact/scql_bench/` | Docker deployment and driver for the SecretFlow-SCQL comparison |

## Reproduce

```sh
cd artifact
python3.12 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python -m unittest discover -s tests -v    # 14 tests, about 1 minute
./run_all.sh                               # downloads data, runs all experiments, rebuilds the paper (about 3 h on an Apple M4)
```

The SCQL comparison needs Docker and Go and is run separately (see `artifact/README.md`).
Latencies depend on the host; query answers are deterministic.

## Build the paper only

```sh
cd paper
pdflatex main && bibtex main && pdflatex main && pdflatex main
```

## Data

UCI Adult (doi:10.24432/C5XW20) and Census-Income (KDD) are downloaded by `run_all.sh`; they are not stored here.
`artifact/scql_bench/deploy/` is adapted from SecretFlow-SCQL (Apache-2.0, `deploy/LICENSE.scql`).

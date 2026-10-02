# Reproduction scripts

- `check_kccs.py`: independent recomputation of every computable vector in
  `kcc-0001/vectors/conformance.json` and `kcc-0002/vectors/authority-schemes.json`
  at kaspanet/kccs `411b41bc`, the prose §6 values of KCC-1, the KCC-2 §4.1 values,
  the KCC-20 dispatch tags, and (optional second argument) the unmerged
  kaspanet/kccs#31 KCC-20 vector file. It includes a small KCC-1 decoder model so the
  30 `rejection_vectors` are executed, with positive controls that must be accepted.
- `blake3_ref.py`: pure-Python BLAKE3 used as a second implementation. Every BLAKE3
  value in `check_kccs.py` is computed with it and with the `blake3` PyPI package and
  asserted equal.

```sh
git clone https://github.com/kaspanet/kccs && git -C kccs checkout 411b41bc14b3fda8f3a0548242c555f3597cad1a
python3 -m venv .venv && .venv/bin/pip install blake3      # used: blake3 1.0.10, Python 3.13.5
.venv/bin/python scripts/check_kccs.py kccs evidence/kccs-pr31-cfb74cfa-kcc-0020-vectors-conformance.json
```

Result on 2026-10-02: `SUMMARY PASS=296 FAIL=0 INFO=15` ([log](../logs/check_kccs.log)).

The Argent reference run is in [`../logs/argent-kcc20-reference-cargo-test.log`](../logs/argent-kcc20-reference-cargo-test.log):

```sh
git clone https://github.com/argent-lang/kcc20-reference && cd kcc20-reference
git fetch origin pull/1/head:pr1 && git checkout 5b2a23124ef43730eca4f69248bc2866daf2c24c
cargo +1.94.1 test --locked --all-targets
```

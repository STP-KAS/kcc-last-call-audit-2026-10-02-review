# Sources

Every source used in this review. All were read only. Nothing was posted, commented, reacted to, tagged or released on any of them.

## Audited object

- STP-KAS/kcc-last-call-audit-2026-10-02 at [`9c9c133b2cfd66e7236085ad02fab343bc62b238`](https://github.com/STP-KAS/kcc-last-call-audit-2026-10-02/tree/9c9c133b2cfd66e7236085ad02fab343bc62b238) (2 commits: `18e166f2` and `9c9c133b`, 2026-10-02 20:15/20:16 CEST). Files: README.md, AUDIT.md, COVERAGE.md, INCONSISTENCIES.md, MASTER-DELTA.md, SECOND-PASS.md, VECTORS.md. Visibility PUBLIC.

## Primary specification sources (kaspanet/kccs)

- Repository: https://github.com/kaspanet/kccs. `main` = [`411b41bc14b3fda8f3a0548242c555f3597cad1a`](https://github.com/kaspanet/kccs/commit/411b41bc14b3fda8f3a0548242c555f3597cad1a) (re-checked with `git ls-remote` during this review). `has_discussions` false.
- Files at that commit: `README.md`, `kcc-0000.md`, `kcc-0001.md`, `kcc-0001/vectors/conformance.json`, `kcc-0002.md`, `kcc-0002/vectors/authority-schemes.json`, `kcc-0002/reference-code.md`, `kcc-0020.md`, `kcc-0020/borrowed-receive-authorization.md`, `kcc-template.md`, `LICENSE.md`.
- Historical blobs: `kcc-0000.md` at `5cf757b6` (#17, merged as Last Call) and `c0bb8f3b` (#25, Final). `kcc-0002.md` at `c0bb8f3b` (keyed `P2PKHHash`). `kcc-0001.md` at `5a17429`, `ba692c6`, `54f4f9c`, `da834af`. `kcc-0020.md` at `e31a5a8`. Full status history: [evidence/kccs-git-history.txt](evidence/kccs-git-history.txt).
- Pull requests (GitHub API, read-only): #2, #17, #18, #20, #24, #25, #26, #27, #29, #30, #31, #32, #33, #34: metadata, reviews, #25 body, #31 reviews and comments. See [evidence/kccs-pr-metadata.txt](evidence/kccs-pr-metadata.txt).
- #31 head `cfb74cfa4d7e25f3e7ec0f9144ad72c460b9d810`: `kcc-0020.md` and `kcc-0020/vectors/conformance.json` (saved as [evidence/kccs-pr31-cfb74cfa-kcc-0020-vectors-conformance.json](evidence/kccs-pr31-cfb74cfa-kcc-0020-vectors-conformance.json)).
- Issues #14 and #28 (state, title).
- Branch `kcc0-finalization` at `63d6924d` (= #25 head).
- Collaborators API: HTTP 403 (needs push access), so editors could not be listed.

## Rendered site

- https://kccs.dev/, https://kccs.dev/kcc-0-purpose-and-guidelines/, https://kccs.dev/kcc-1-covenant-concepts-and-abi/, https://kccs.dev/kcc-2-authority-schemes/, https://kccs.dev/kcc-20-fungible-token-covenant/ (fetched with curl on 2026-10-02; string checks only).

## KIPs

- https://github.com/kaspanet/kips master = `e4ae2332117b5cb68bd6188e065ef885b6d17939` (committed 2026-07-15T12:19:57Z).
- [kip-0017.md @ e4ae2332](https://github.com/kaspanet/kips/blob/e4ae2332117b5cb68bd6188e065ef885b6d17939/kip-0017.md) and [kip-0020.md @ e4ae2332](https://github.com/kaspanet/kips/blob/e4ae2332117b5cb68bd6188e065ef885b6d17939/kip-0020.md) (headers).

## Node implementation (rusty-kaspa)

- https://github.com/kaspanet/rusty-kaspa master = `01b532e8b553523216471682649693af92f0fd16` (2026-09-22T13:50:54Z).
  - [crypto/txscript/src/data_stack.rs L127-L160](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/data_stack.rs#L127-L160) (`serialize_i64`).
  - [crypto/txscript/src/opcodes/mod.rs L1297-L1304](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/opcodes/mod.rs#L1297-L1304) (`OpNum2Bin`).
  - [crypto/txscript/src/script_builder.rs L274-L294](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/script_builder.rs#L274-L294) (`add_i64`).

## Reference implementation (Argent)

- https://github.com/argent-lang/kcc20-reference: `master` = `76648f9938c474a5210f4b3b59b2e1b9ebae420f` ("initial"). PR #1 open, unmerged, head `5b2a23124ef43730eca4f69248bc2866daf2c24c` (updated 2026-10-02T13:45:06Z, author Manyfestation).
- At that head: `contracts/kcc20.ag`, `src/bin/kcc20/tests.rs`, `Cargo.toml`, commit `707acca` ("Use unkeyed BLAKE3 for P2PKH owner hashes"). `cargo +1.94.1 test --locked --all-targets` was run: [logs/argent-kcc20-reference-cargo-test.log](logs/argent-kcc20-reference-cargo-test.log).

## Comments-URI threads (Kas-Smiths Discourse JSON, saved in `evidence/`)

- https://kas-smiths.org/t/kcc-01-discussion-thread/141.json
- https://kas-smiths.org/t/kcc-02-control-principal-references-in-program-abis/95.json
- https://kas-smiths.org/t/8.json
- https://kas-smiths.org/posts/354.json, https://kas-smiths.org/posts/355.json, https://kas-smiths.org/posts/364.json

## X posts (read through the X API, saved in [evidence/x-posts-2026-10-02.json](evidence/x-posts-2026-10-02.json))

- https://x.com/kccforum/status/2105991195583488410 (2026-10-02T12:00:03Z)
- https://x.com/kccforum/status/2106008195114381508 (2026-10-02T13:07:36Z)
- https://x.com/manyfest_/status/2106012029358047445 (2026-10-02T13:22:50Z)

## STP-KAS context

- https://github.com/STP-KAS/kaspa-master-file `main` = `99ae9620dd580ff0630cd720f83a0e78de616f4e` (2026-10-02T19:50:28+02:00): README.md rows "KCC still open" and "KCC20 reference", `master.json`.
- The challenger's private copy of the master file (not named here because it is private; README read, last pushed 2026-09-29).

## Tools

- Python 3.13.5, `blake3` 1.0.10 (PyPI), `hashlib.blake2b`, and a pure-Python BLAKE3 ([scripts/blake3_ref.py](scripts/blake3_ref.py)) cross-checked against the package on inputs of 0 to 8193 bytes, keyed and unkeyed.
- Rust 1.94.1 via rustup, for the Argent tests.
- `git`, `gh` (read-only API calls), `curl`.

# Independent review: KCC Last Call audit (2026-10-02)

> **Challenge context.** The audit repositories of 2026-10-02 are part of the challenge between the **bot side** (kaspa master challenge / kaspa master bot) and the **build side** (Grok Build / kaspa master prompt build). **This repository is an independent review in that challenge.** It checks one audit against primary sources and does not take a side.

| | |
| --- | --- |
| Reviewed repo | [STP-KAS/kcc-last-call-audit-2026-10-02](https://github.com/STP-KAS/kcc-last-call-audit-2026-10-02) |
| Reviewed commit | [`9c9c133b2cfd66e7236085ad02fab343bc62b238`](https://github.com/STP-KAS/kcc-last-call-audit-2026-10-02/tree/9c9c133b2cfd66e7236085ad02fab343bc62b238) ("Second pass: quote the KCC-20 reply and record what held.") |
| Object of that audit | [kaspanet/kccs](https://github.com/kaspanet/kccs) `main` at [`411b41bc14b3fda8f3a0548242c555f3597cad1a`](https://github.com/kaspanet/kccs/commit/411b41bc14b3fda8f3a0548242c555f3597cad1a): KCC-0, KCC-1, KCC-2, KCC-20 |
| Review date | 2026-10-02 |
| Full findings | [FINDINGS.md](FINDINGS.md) |
| Sources | [SOURCES.md](SOURCES.md) |
| Reproduction | [scripts/](scripts/) and [logs/](logs/) |

KCC means Kaspa Call for a Convention ([KCC-0 §1](https://github.com/kaspanet/kccs/blob/411b41bc14b3fda8f3a0548242c555f3597cad1a/kcc-0000.md#L35-L54)): voluntary ecosystem conventions, not consensus changes. On 2026-10-01, KCC-1 (covenant ABI) and KCC-2 (authority schemes) were set to `Last Call`. KCC-20 (fungible token) is still `Draft`.

## Verdict

**Sound, with corrections.** The audit is accurate and carefully sourced. Every line citation, SHA, merge time, forum count, X-post quote and hash checked here reproduces. No fabricated fact was found. Its three blockers are real gaps between the text and KCC-0:

- LC-1: no `Last-Call-Deadline`;
- LC-2: §4.3 still says "retain Draft";
- LC-3: KCC-20 on `main` is not shippable.

Three corrections matter before anyone relies on it:

1. **LC-7 is mis-reasoned** (KR-01). An eight-byte ScriptNum *is* the signed-magnitude payload in rusty-kaspa.
2. **LC-1 leaves out the editors' own precedent** (KR-02). KCC-0 ran its Last Call with no deadline header and was finalized on a 14-day count from the merge. So "the clock is not running" is not how the editors have behaved. Assume about 2026-10-15 ~12:30Z.
3. **It misses a KCC-2 ambiguity** (KR-04): `pubkey` vs `byte[32]` for scheme-selected fields changes dispatch tags. This belongs on the KCC-2 Last Call list.

## Scope and method

1. Cloned the audited repo and read all 7 files.
2. Cloned kaspanet/kccs and checked every cited line number, header and section against `411b41bc`. Walked the status history of each KCC file through git. Pulled PR metadata, reviews and bodies (#2, #17, #18, #20, #24-#27, #29-#34) read-only.
3. Wrote an independent checker ([scripts/check_kccs.py](scripts/check_kccs.py)) that recomputes **every** computable KCC-1 and KCC-2 JSON vector, the KCC-1 §6 prose values, the 30 KCC-1 rejection vectors (decoder model with positive controls), the 20 KCC-2 approval checks, the KCC-20 tags, and the unmerged #31 KCC-20 vectors. BLAKE3 is computed with two independent implementations. Result: **296 PASS / 0 FAIL** ([log](logs/check_kccs.log)).
4. Checked out argent-lang/kcc20-reference PR #1 head `5b2a2312` and ran `cargo test`: **47 passed / 0 failed** ([log](logs/argent-kcc20-reference-cargo-test.log)).
5. Re-read the cited external sources:
   - KIP-17 and KIP-20 at `e4ae2332`;
   - rusty-kaspa `serialize_i64`, `OpNum2Bin` and `add_i64` at `01b532e8`;
   - the Kas-Smiths Comments-URI JSON;
   - the three X posts (X API);
   - kccs.dev;
   - STP-KAS/kaspa-master-file `99ae9620`.
6. Teammate agents (kaspa master challenge, kaspa master bot) could not be messaged from this worker. Their last public material was read instead (see [FINDINGS.md Part C](FINDINGS.md#part-c-could-not-be-verified)).

Hard limits kept: nothing was posted, commented or reacted to on any repository outside STP-KAS. The audited repo was not modified. No tags or releases.

## Findings table

New findings from this review:

| ID | Severity | One line |
| --- | --- | --- |
| [KR-01](FINDINGS.md#kr-01-lc-7s-reasoning-is-wrong-an-eight-byte-scriptnum-is-the-signed-magnitude-payload) | medium | LC-7 is wrong: 8-byte ScriptNum = signed-magnitude payload (`serialize_i64(v, Some(8))`, `OpNum2Bin`). Downgrade to editorial. |
| [KR-02](FINDINGS.md#kr-02-lc-1-leaves-out-the-editors-own-precedent-kcc-0-ran-its-last-call-with-no-deadline-header-and-a-14-day-count-from-the-merge) | medium | LC-1 leaves out the #17/#25 precedent: KCC-0 went Last Call→Final with no deadline header, on a 14-day count from the merge. The effective window likely ends about 2026-10-15. |
| [KR-04](FINDINGS.md#kr-04-new-kcc-2-ambiguity-one-scheme-selected-field-cannot-have-the-type-specified-in-the-table) | medium | New KCC-2 defect: "MUST have the type specified in the table" vs a multi-scheme field. `byte[32]`→`79c71c23`, `pubkey`→`4bf4b1a6`. |
| [KR-03](FINDINGS.md#kr-03-kcc-0-itself-does-not-meet-several-of-its-own-rules-and-the-audit-only-hedges-on-this) | low | KCC-0 itself: no Comments-URI, never Draft/Review, `Created` ≠ merge date, README out of sync for 5 weeks. |
| [KR-05](FINDINGS.md#kr-05-lc-9-understates-the-kcc-1-humanmachine-vector-gap) | low | KCC-1 also has JSON-only vectors (30 rejections, 6 tags). LC-9's "in both" is inaccurate. |
| [KR-07](FINDINGS.md#kr-07-lc-10-holds-with-a-sharper-framing-and-stronger-evidence) | low | LC-10 holds. The gap is the unrestricted sighash type, and the Argent reference has a test accepting all 6 types. |
| [KR-10](FINDINGS.md#kr-10-unanswered-technical-questions-on-the-kcc-1-comments-uri) | low | The KCC-1 Comments-URI has 4 unanswered questions from a co-author. One is still unaddressed in the text. |
| [KR-11](FINDINGS.md#kr-11-the-audit-calls-itself-private-but-the-repository-is-public) | low | The audit calls itself "Private", but the repo is public. |
| [KR-06](FINDINGS.md#kr-06-the-audits-vector-check-is-narrow-and-not-reproducible-this-review-re-ran-it-fully-296-pass-0-fail) | info | The audit's checker is not shipped and covers a subset. Full rerun here: 296/0. All audit hashes reproduce. |
| [KR-08](FINDINGS.md#kr-08-the-audits-description-of-open-kaspanetkccs31-is-accurate-but-incomplete) | info | #31 is approved (unmerged), its vectors recompute, it makes the prose authoritative, and it adds a stale "§8.1" citation. |
| [KR-09](FINDINGS.md#kr-09-argent-kcc20-reference-pr-1-tests-run-and-pass-4747-closing-an-audit-gap) | info | Argent PR #1 tests: 47/47 pass. It follows the prose (owner preserved), not the shorter pseudocode. |
| [KR-12](FINDINGS.md#kr-12-an-earlier-public-stp-kas-comment-on-kccs31-is-contradicted-by-the-audits-correct-lc-11) | info | An earlier STP-KAS comment on kccs#31 gave the wrong KCC-20 merge date. The audit's LC-11 is right. |
| [KR-13](FINDINGS.md#kr-13-small-citation-and-attribution-issues-in-the-audit) | info | Small citation and attribution nits. |
| [KR-14](FINDINGS.md#kr-14-stale-reference-titles-in-kcc-2-and-kcc-20-not-in-the-audit) | info | Stale KCC-1 title in the KCC-2/KCC-20 reference lists. |

The audit's own findings:

| Audit ID | Audit verdict | Review result |
| --- | --- | --- |
| LC-1 | blocker | Confirmed defect; consequence overstated (KR-02) |
| LC-2 | blocker | Confirmed |
| LC-3 | blocker | Confirmed (item 10 not re-verified; item 6 better filed under KCC-2) |
| LC-4 | should-fix | Confirmed (all forum counts exact) |
| LC-5 | should-fix | Confirmed |
| LC-6 | should-fix | Confirmed (the JSON is the newer intent, from #27) |
| LC-7 | should-fix | Partly incorrect: downgrade to info (KR-01) |
| LC-8 | should-fix | Confirmed |
| LC-9 | should-fix before Final | Confirmed; understated for KCC-1 (KR-05) |
| LC-10 | should-fix | Confirmed with nuance (KR-07) |
| LC-11 | nit | Confirmed, including KCC-0 |
| LC-12 | holds | Confirmed and extended (296/0) |

## What this review could not do

See [FINDINGS.md Part C](FINDINGS.md#part-c-could-not-be-verified). In short:

- the July topic-8 ABI comparison;
- kaspaexplained;
- the list of KCC editors (403);
- inline review threads on #27/#30;
- #31 vs #20 reject rows;
- Silverscript source;
- direct teammate messaging.

---

Prepared for STP-KAS as an independent review. Not Kaspa core, not an official KCC process document. Primary sources win over this file.

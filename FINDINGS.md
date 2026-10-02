# Findings

Review of [STP-KAS/kcc-last-call-audit-2026-10-02](https://github.com/STP-KAS/kcc-last-call-audit-2026-10-02) at
[`9c9c133b2cfd66e7236085ad02fab343bc62b238`](https://github.com/STP-KAS/kcc-last-call-audit-2026-10-02/tree/9c9c133b2cfd66e7236085ad02fab343bc62b238)
("the audit"), which audits [kaspanet/kccs](https://github.com/kaspanet/kccs) `main` at
[`411b41bc14b3fda8f3a0548242c555f3597cad1a`](https://github.com/kaspanet/kccs/tree/411b41bc14b3fda8f3a0548242c555f3597cad1a). Review date 2026-10-02.

Link shorthands used below (all commit-pinned):

- `K/…` = `https://github.com/kaspanet/kccs/blob/411b41bc14b3fda8f3a0548242c555f3597cad1a/…`
- `A/…` = `https://github.com/STP-KAS/kcc-last-call-audit-2026-10-02/blob/9c9c133b2cfd66e7236085ad02fab343bc62b238/…`

Times are UTC (marked `Z`) as the sources give them. Add 2 hours for Brussels time (CEST).

Severity is the severity of the problem **in the audit** (how much it would mislead a reader), except where a finding is a new defect in the KCC text, which is labelled "new KCC defect".

Contents:

1. [Part A: new findings (KR-01 to KR-14)](#part-a-new-findings)
2. [Part B: verdict on each audit finding (LC-1 to LC-12) and the other audit files](#part-b-verdict-on-each-audit-finding)
3. [Part C: could not be verified](#part-c-could-not-be-verified)
4. [Part D: open questions](#part-d-open-questions)

---

## Part A: new findings

### KR-01: LC-7's reasoning is wrong. An eight-byte ScriptNum *is* the signed-magnitude payload

- **Severity:** medium
- **Claim.** [A/AUDIT.md#L131-L140](https://github.com/STP-KAS/kcc-last-call-audit-2026-10-02/blob/9c9c133b2cfd66e7236085ad02fab343bc62b238/AUDIT.md#L131-L140), especially line 134: "ScriptNum and signed-magnitude are different byte strings for the same integer. ... An implementer who encodes state as ScriptNum will not match the vector." LC-7 is rated should-fix.
- **What is wrong.** In Kaspa, ScriptNum *is* little-endian signed-magnitude with the sign in the high bit of the last byte. A ScriptNum encoded to a fixed eight-byte width produces exactly the KCC-1 state payload. Only the *minimal* ScriptNum (the argument form) is a different byte string, and the table cell separates the two ("Eight-byte ScriptNum; minimal ScriptNum as a standalone argument").
- **Evidence.**
  - rusty-kaspa `serialize_i64(from, size)` writes the magnitude little-endian, pads it to `size`, then ORs `0x80` into the last byte for negatives: [data_stack.rs L127-L160 @ 01b532e8](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/data_stack.rs#L127-L160). `OpNum2Bin` calls `serialize_i64(num, Some(size))`: [opcodes/mod.rs L1297-L1304](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/opcodes/mod.rs#L1297-L1304). So `OpNum2Bin(-5, 8)` = `0500000000000080`, which is the KCC-1 vector ([K/kcc-0001.md#L870](https://github.com/kaspanet/kccs/blob/411b41bc14b3fda8f3a0548242c555f3597cad1a/kcc-0001.md#L870)).
  - `check_kccs.py`, section "KCC-1 audit LC-7": for 17, −5, −1, 128, −128, ±(2^63−1), the 8-byte sized ScriptNum equals the signed-magnitude payload (7/7 PASS, [log](logs/check_kccs.log)).
  - The Argent reference decodes the state threshold with `OpBin2Num(borrow_guard.slice(0, 8))`, which treats the eight-byte payload as a ScriptNum ([kcc20.ag L132 @ 5b2a2312](https://github.com/argent-lang/kcc20-reference/blob/5b2a23124ef43730eca4f69248bc2866daf2c24c/contracts/kcc20.ag#L132)).
- **What still holds.** §3.4.3 says "signed-magnitude" and §3.4.4 says "ScriptNum". Two names for one encoding is a small clarity issue. The audit's suggested cell text is fine as an editorial improvement.
- **Recommendation.** Downgrade LC-7 to info/editorial. Replace line 134 with: "Both names describe the same bytes at width 8 (rusty-kaspa `serialize_i64(v, Some(8))` / `OpNum2Bin(v, 8)`). The table should name the width and the sign bit once, so a reader does not think two encodings exist."

### KR-02: LC-1 leaves out the editors' own precedent. KCC-0 ran its Last Call with no deadline header and a 14-day count from the merge

- **Severity:** medium
- **Claim.** [A/README.md#L27](https://github.com/STP-KAS/kcc-last-call-audit-2026-10-02/blob/9c9c133b2cfd66e7236085ad02fab343bc62b238/README.md#L27): "Until that header exists, KCC-0's clock is not running." LC-1 ([A/AUDIT.md#L28-L43](https://github.com/STP-KAS/kcc-last-call-audit-2026-10-02/blob/9c9c133b2cfd66e7236085ad02fab343bc62b238/AUDIT.md#L28-L43)) treats the window as not open.
- **What is missing.** The missing-header defect is real (see LC-1, confirmed). But the same editors have already shown how they read that rule:
  - KCC-0 was merged on 2026-08-27 by [#17](https://github.com/kaspanet/kccs/pull/17) (`5cf757b`) **directly as `Status: Last Call`**. That version already contained the `Last-Call-Deadline` requirement, and its preamble had no such header ([kcc-0000.md @ 5cf757b](https://github.com/kaspanet/kccs/blob/5cf757b63467b8c3fa4a290973d171063164be21/kcc-0000.md#L1-L9)).
  - [#25](https://github.com/kaspanet/kccs/pull/25) moved it to Final (merged 2026-09-21T13:31:53Z by IzioDev). Its body says: "KCC0 was moved to `Last Call` on August 27. Today is `September 11` and 15 days have passed since then. As per `KCC0` after 14 days of `Last Call` status, the KCC standard is `Final`." ([evidence/kccs-pr-metadata.txt](evidence/kccs-pr-metadata.txt)).
  - So the editors' practice so far is a 14-day count from the status-change merge, with no header. For KCC-1 and KCC-2, that count runs from #32 (merged 2026-10-01T12:33:08Z) and #33 (2026-10-01T12:52:21Z), giving about **2026-10-15 12:33Z / 12:52Z**. The audit mentions 2026-10-15 as arithmetic only ([A/AUDIT.md#L31](https://github.com/STP-KAS/kcc-last-call-audit-2026-10-02/blob/9c9c133b2cfd66e7236085ad02fab343bc62b238/AUDIT.md#L31)).
- **Why it matters.** If a reader trusts "the clock is not running" and waits, they may miss the window the editors are actually likely to use. #25 also shows that "after 14 days ... is Final" is being read as automatic. That makes the audit's LC-9 point (Final is not automatic for Standards Track) more important, not less.
- **Recommendation.** Keep LC-1 as a process defect. Replace "the clock is not running" with: "Formally, KCC-0 has set no end date. In practice the editors counted 14 days from the status merge for KCC-0 (#25). Assume objections must be raised before 2026-10-15 ~12:30Z." Cite #17 and #25.

### KR-03: KCC-0 itself does not meet several of its own rules, and the audit only hedges on this

- **Severity:** low (new KCC defect, process only)
- **Evidence.**
  - No `Comments-URI` in KCC-0's preamble ([K/kcc-0000.md#L1-L9](https://github.com/kaspanet/kccs/blob/411b41bc14b3fda8f3a0548242c555f3597cad1a/kcc-0000.md#L1-L9)). The header is "required from Review onward" (line 274). §4.2 also says a normative defect correction in a Final KCC "must be announced at the KCC's `Comments-URI`" (lines 160-162), and KCC-0 has none.
  - KCC-0 never went through Draft or Review. Its first commit is already Last Call (above). §4.2 says "Every KCC follows it, including this one" (line 132).
  - `Created: 2026-08-25` (line 8), but it was merged on 2026-08-27T13:35:10Z (#17). The audit's LC-11 hedges on this ("recorded from the headers and the commit list in the read pass", [A/AUDIT.md#L187](https://github.com/STP-KAS/kcc-last-call-audit-2026-10-02/blob/9c9c133b2cfd66e7236085ad02fab343bc62b238/AUDIT.md#L187)). The mismatch is confirmed here.
  - The README listed KCC-0 as `Draft` from #17 (2026-08-27) until #34 (2026-10-01), while the file said Last Call and then Final. #25 changed only `kcc-0000.md` (1 file, 1 line), although §4.2 says the README "is updated in the same pull request as any status change" (lines 193-195). ([evidence/kccs-git-history.txt](evidence/kccs-git-history.txt))
- **Recommendation.** Add this to the audit as context for LC-1/LC-2/LC-11. It also gives a softer reading of LC-2: the process document has not been applied strictly even to itself. Fix: add a `Comments-URI` to KCC-0 and correct `Created`, or record why not.

### KR-04: New KCC-2 ambiguity. One scheme-selected field cannot have the "type specified in the table"

- **Severity:** medium (new KCC defect in KCC-2, which is in Last Call)
- **Claim in KCC-2.** [K/kcc-0002.md#L50-L56](https://github.com/kaspanet/kccs/blob/411b41bc14b3fda8f3a0548242c555f3597cad1a/kcc-0002.md#L50-L56) gives `0x00` the type `pubkey` and `0x01`-`0x04` the type `byte[32]`. Lines 83-84: "Authority values MUST have the type and exact payload length specified in the table." Lines 156-157 give, as the model, KCC-20 storing every scheme's value in one `state.owner` field selected by `state.owner_scheme`.
- **Problem.** A single field has one declared KCC-1 type. If it is `byte[32]` (as in KCC-20, [K/kcc-0020.md#L34](https://github.com/kaspanet/kccs/blob/411b41bc14b3fda8f3a0548242c555f3597cad1a/kcc-0020.md#L34)), then `0x00` values do not have "the type specified in the table". If it is `pubkey`, the other four do not. The payload bytes are identical (32 bytes either way). But `TypeName` feeds the dispatch tag:
  - `transfer({int,byte[32],byte,byte,byte[32],byte[32]}[],byte[])` → `79c71c23`
  - `transfer({int,pubkey,byte,byte,byte[32],byte[32]}[],byte[])` → `4bf4b1a6`

  (both computed by `check_kccs.py`). Two implementers who follow KCC-2 literally can therefore produce incompatible ABIs. KCC-0 §12.1 calls "an ambiguity that two conforming implementations could resolve differently" a blocking objection ([K/kcc-0000.md#L396-L398](https://github.com/kaspanet/kccs/blob/411b41bc14b3fda8f3a0548242c555f3597cad1a/kcc-0000.md#L396-L398)).
- **Mitigation already in the texts.** KCC-1 §3.4.8 allows public keys to "remain `byte[32]` values with distinct semantic annotations" ([K/kcc-0001.md#L370-L380](https://github.com/kaspanet/kccs/blob/411b41bc14b3fda8f3a0548242c555f3597cad1a/kcc-0001.md#L370-L380)). The Argent reference and the #31 vectors both use `byte[32]` and `79c71c23`. Practice has converged. The KCC-2 sentence has not.
- **Relation to the audit.** The audit raises this only as KCC-20 item 6 ([A/AUDIT.md#L78](https://github.com/STP-KAS/kcc-last-call-audit-2026-10-02/blob/9c9c133b2cfd66e7236085ad02fab343bc62b238/AUDIT.md#L78)). The defect sits in KCC-2, which is in Last Call, so it belongs on the KCC-2 list.
- **Recommendation (for the KCC-2 Last Call).** One sentence in KCC-2 §2.1: "A field that holds values of several schemes is typed `byte[32]`. A `p2pk-schnorr/v1` value in such a field is the 32-byte public key (a semantic annotation per KCC-1 §3.4.8)." Or make the `0x00` column read `pubkey or byte[32]`.

### KR-05: LC-9 understates the KCC-1 human/machine vector gap

- **Severity:** low
- **Claim.** [A/AUDIT.md#L165](https://github.com/STP-KAS/kcc-last-call-audit-2026-10-02/blob/9c9c133b2cfd66e7236085ad02fab343bc62b238/AUDIT.md#L165): "KCC-1's constructions are in both the markdown §6 and the JSON. The state-length pair in LC-6 is the place they disagree."
- **What is wrong.** `kcc-0001/vectors/conformance.json` has many vectors with no counterpart in `kcc-0001.md` §6:
  - all 30 `rejection_vectors`;
  - the zero-argument dispatch tag `tick()` → `161bd7ee` (§3.5.1 defines that construction at [L422-L423](https://github.com/kaspanet/kccs/blob/411b41bc14b3fda8f3a0548242c555f3597cad1a/kcc-0001.md#L420-L423));
  - record-dispatch tags `dafff68f`, `81764c55`, `3d042cd2`, `a625f54c`;
  - the collision tag `33b057f4`;
  - extra scalar, composite and data-push rows.

  None of these strings appear in the markdown ([log](logs/check_kccs.log), INFO lines). KCC-0 §5 says vectors "cover every construction ... provided both in the document and in machine-readable form ... The two must agree" ([K/kcc-0000.md#L235-L240](https://github.com/kaspanet/kccs/blob/411b41bc14b3fda8f3a0548242c555f3597cad1a/kcc-0000.md#L235-L240)). This is the same gap the audit flags for KCC-2 `approval_checks`/`registry_checks`.
- **Recommendation.** Extend LC-9's proposed fix to KCC-1: either restate the JSON-only rows in §6, or add one sentence making the JSON the human list by inclusion.

### KR-06: The audit's vector check is narrow and not reproducible. This review re-ran it fully: 296 PASS, 0 FAIL

- **Severity:** info (confirmation, plus a reproducibility gap in the audit)
- **Claim.** [A/VECTORS.md#L7](https://github.com/STP-KAS/kcc-last-call-audit-2026-10-02/blob/9c9c133b2cfd66e7236085ad02fab343bc62b238/VECTORS.md#L7): "The checker is not part of this repo." It checked 3 of the 4 template rows and skipped the `6162|63` row, data pushes, scalar edge cases, composites, 4 of 6 record-dispatch tags, the zero-argument tag, template views, continuation, the virtual element, and the 30 rejection vectors ([A/VECTORS.md#L69-L75](https://github.com/STP-KAS/kcc-last-call-audit-2026-10-02/blob/9c9c133b2cfd66e7236085ad02fab343bc62b238/VECTORS.md#L69-L75) is honest about part of this).
- **Result here.** [`scripts/check_kccs.py`](scripts/check_kccs.py) recomputes every computable KCC-1 and KCC-2 JSON vector. It runs all 30 rejection vectors through a small decoder model, with positive controls. It runs all 20 KCC-2 `approval_checks` against a minimum-check model (signature validity taken from the oracle). It also checks the #31 KCC-20 vectors. Each BLAKE3 value is computed with two independent implementations. Result: **PASS 296, FAIL 0** ([log](logs/check_kccs.log)). Every hash printed in the audit's LC-3, LC-8, LC-12 and VECTORS.md reproduces exactly, including `79c71c23`, `fd3ef14a`, `91438cfb…`, `4ba1a5f9…`, `7caa514a…`, `ed887ad1…`, `6437b3ac…`.
- **Recommendation.** Ship the checker in the audit repo (or link this one) so the "FAILS 0" claim can be reproduced.

### KR-07: LC-10 holds, with a sharper framing and stronger evidence

- **Severity:** low (wording correction; the substance of LC-10 stands)
- **Claim.** [A/AUDIT.md#L174](https://github.com/STP-KAS/kcc-last-call-audit-2026-10-02/blob/9c9c133b2cfd66e7236085ad02fab343bc62b238/AUDIT.md#L174): KCC-20 "does not define the bytes that the signature covers."
- **Nuance.** KCC-20 types the borrow witness as KCC-1 `sig`, a "65-byte transaction signature" ([K/kcc-0001.md#L182](https://github.com/kaspanet/kccs/blob/411b41bc14b3fda8f3a0548242c555f3597cad1a/kcc-0001.md#L182), [K/kcc-0020.md#L230-L231](https://github.com/kaspanet/kccs/blob/411b41bc14b3fda8f3a0548242c555f3597cad1a/kcc-0020.md#L230-L231)). Under the consensus `OpCheckSig`, the message is the transaction sighash chosen by the trailing hash-type byte. The real gap is that **the hash type is not restricted**. That is exactly what the audit's own fix targets, and what #31 admits ("does not restrict the sighash type", #31 `kcc-0020.md` line 452).
- **Stronger evidence (not in the audit).** The Argent reference has a test named `signature_schemes_accept_all_consensus_sighash_types`. It builds valid owner transfers (P2PK, P2PKH-Schnorr, P2PKH-ECDSA) and a `schnorr-signature/v1` borrow under hash types `0x01, 0x02, 0x04, 0x81, 0x82, 0x84` ([tests.rs L980-L997 @ 5b2a2312](https://github.com/argent-lang/kcc20-reference/blob/5b2a23124ef43730eca4f69248bc2866daf2c24c/src/bin/kcc20/tests.rs#L980-L997)). It passed in this review's run. So the candidate reference deliberately accepts `SIGHASH_NONE`/`SINGLE`/`ANYONECANPAY` for borrow signatures.
- **Recommendation.** Reword LC-10's "What" to "does not restrict the sighash type of the borrow signature." Cite the Argent test. Keep should-fix.

### KR-08: The audit's description of open kaspanet/kccs#31 is accurate but incomplete

- **Severity:** info
- **Evidence** (PR head [`cfb74cfa`](https://github.com/kaspanet/kccs/pull/31), read-only):
  - #31 has an **APPROVED** review by Manyfestation (2026-09-28T10:57:38Z), its only approval. It is still open and unmerged ([evidence/kccs-pr-metadata.txt](evidence/kccs-pr-metadata.txt)).
  - #31 adds `kcc-0020/vectors/conformance.json`. Its dispatch tags `79c71c23`/`fd3ef14a`, 112-byte state encoding, grouped argument pushes, witness lengths, unkeyed P2PKH hashes and hash-chain links all recompute ([log](logs/check_kccs.log), "#31" lines). So the audit's derived KCC-20 tags (LC-3 item 6) have an independent author-side match.
  - #31 states that where the pseudocode and the prose state the same rule, "the prose is authoritative" (#31 `kcc-0020.md` lines 255-256). That would settle LC-3 item 7's "which wins" question, but only once merged.
  - #31 adds a new stale citation: "KCC-1 Section 8.1 requires a state layout of statically known width" (line 306). KCC-1 §8 is References, and KCC-1 §3.7.1 explicitly allows `string` and dynamic arrays in state ([K/kcc-0001.md#L512-L514](https://github.com/kaspanet/kccs/blob/411b41bc14b3fda8f3a0548242c555f3597cad1a/kcc-0001.md#L512-L514)). The real fixed-width constraint is §3.4.6 (arrays of records), because `transfer` takes `KCC20State[]`.
  - The other #31 points in the audit are confirmed: `Status: Last Call` with no `Last-Call-Deadline`, "Section 9.1"/"Section 10" citations, `P2PKHHash` name, and the unrestricted-sighash sentence.
- **Recommendation.** Add the approval state and the prose-authority sentence to LC-3, and the §8.1 citation to the list of fixes #31 still needs.

### KR-09: Argent `kcc20-reference` PR #1 tests run and pass (47/47), closing an audit gap

- **Severity:** info
- **Claim.** [A/VECTORS.md#L79](https://github.com/STP-KAS/kcc-last-call-audit-2026-10-02/blob/9c9c133b2cfd66e7236085ad02fab343bc62b238/VECTORS.md#L79): "did not check out that head and did not run `cargo test`."
- **Result.** At head `5b2a23124ef43730eca4f69248bc2866daf2c24c`, `cargo +1.94.1 test --locked --all-targets` gave **47 passed, 0 failed** ([log](logs/argent-kcc20-reference-cargo-test.log)).
- **What the run shows:**
  - The reference uses unkeyed `blake3(public_key)` for P2PKH since commit `707acca` (2026-09-18), and has a test rejecting the legacy keyed `PublicKeyHash` (`p2pkh_rejects_legacy_domain_hashes_for_both_roles`).
  - It asserts tags `79c71c23`/`fd3ef14a` (`reference_preserves_kcc20_state_layout_and_dispatch_tags`).
  - On the borrow path it checks `next_states[0].owner == owner` and `owner_scheme` ([kcc20.ag L164-L165](https://github.com/argent-lang/kcc20-reference/blob/5b2a23124ef43730eca4f69248bc2866daf2c24c/contracts/kcc20.ag#L164-L165)) and the sompi value (L172). Those are checks the KCC-20 pseudocode omits (LC-3 item 7). The reference follows the prose.
- **Limits.** These are the implementation's own tests. No KCC-20 machine vectors exist on kccs `main` to run it against. It does not load #31's JSON. It is not linked from `kcc-0020.md`. It is not a KCC-0 Final-gate pass. `cargo clippy` was not run.

### KR-10: Unanswered technical questions on the KCC-1 Comments-URI

- **Severity:** low (new process observation; the audit quotes the post but does not flag it as unanswered)
- **Evidence.** Topic 141 has exactly one post: [post 354](https://kas-smiths.org/posts/354.json), OriNewman (a KCC-1 co-author), 2026-08-29T08:35:42Z. It asks four things:
  1. why `int` arguments use minimal ScriptNum rather than `ScriptBuilder::add_i64`;
  2. `bool` false encoding;
  3. what "This restriction" refers to in §3.4.6;
  4. whether `PushMinimal` should be in the standard at all.

  No reply is on the thread (`posts_count` 1, [evidence](evidence/kas-smiths-t_kcc-01-discussion-thread_141.json)). The §3.4.6 sentence is unchanged at [K/kcc-0001.md#L306-L308](https://github.com/kaspanet/kccs/blob/411b41bc14b3fda8f3a0548242c555f3597cad1a/kcc-0001.md#L306-L308).
- **Reviewer's analysis (not on the thread).** Question 1 looks moot on the current text: rusty-kaspa `add_i64` emits `OP_0`, `OP_1NEGATE`/`OP_1..OP_16`, or a minimal ScriptNum push ([script_builder.rs L274-L294 @ 01b532e8](https://github.com/kaspanet/rusty-kaspa/blob/01b532e8b553523216471682649693af92f0fd16/crypto/txscript/src/script_builder.rs#L274-L294)). That is byte-identical to KCC-1's `PushMinimal(minimal ScriptNum)`. For question 2, standalone `bool` arguments use `OP_0`/`OP_1` ([K/kcc-0001.md#L256](https://github.com/kaspanet/kccs/blob/411b41bc14b3fda8f3a0548242c555f3597cad1a/kcc-0001.md#L256)). Only the state payload uses `00`/`01`.
- **Recommendation.** KCC-0 §7 says substantive discussion should live on the Comments-URI ([K/kcc-0000.md#L297-L299](https://github.com/kaspanet/kccs/blob/411b41bc14b3fda8f3a0548242c555f3597cad1a/kcc-0000.md#L297-L299)). The audit's LC-4 should note that the KCC-1 thread holds four unanswered questions from a co-author and that question 3 is unaddressed in the text. Last Call is the time to close them.

### KR-11: The audit calls itself "private", but the repository is public

- **Severity:** low
- **Evidence.** [A/README.md#L3](https://github.com/STP-KAS/kcc-last-call-audit-2026-10-02/blob/9c9c133b2cfd66e7236085ad02fab343bc62b238/README.md#L3) says "Private working note ... No public post". [A/AUDIT.md#L3](https://github.com/STP-KAS/kcc-last-call-audit-2026-10-02/blob/9c9c133b2cfd66e7236085ad02fab343bc62b238/AUDIT.md#L3) says "Private." The first commit message is "Private KCC Last Call audit ...". GitHub reports `visibility: PUBLIC` (created 2026-10-02T18:15:34Z).
- **Recommendation.** Make the wording match the visibility. That is the owner's choice. This review did not change the audited repo.

### KR-12: An earlier public STP-KAS comment on kccs#31 is contradicted by the audit's correct LC-11

- **Severity:** info (housekeeping for the STP-KAS record; no action was taken on kaspanet)
- **Evidence.** An STP-KAS comment on kaspanet/kccs#31 (2026-09-22T11:10:38Z) said: "`Created` on main is `2026-07-15`, the date this file was merged as Draft." Git shows `kcc-0020.md` was added by [#2](https://github.com/kaspanet/kccs/pull/2) as `e31a5a85` on 2026-08-21 (merged 2026-08-20T23:13:31Z). The audit's LC-11 states this correctly.
- **Recommendation.** Note it internally. The hard rules for this review forbid commenting on kaspanet repos, so nothing was posted.

### KR-13: Small citation and attribution issues in the audit

- **Severity:** info
  - LC-3 item 3 says KCC-20 "Lines 4–5 are `Name <email>` only". `Authors` is line 5 only. Line 4 is `Title`.
  - LC-1/LC-2 say #32/#33 were merged by michaelsutton (correct). They leave out that #32, #33 and #34 were all opened by IzioDev, the lead author of KCC-1 and KCC-2, and approved only by michaelsutton, a co-author. Approval to merge took 10 s, 9 s and 7 s (12:32:58Z→12:33:08Z, 12:52:12Z→12:52:21Z, 13:15:13Z→13:15:20Z). KCC-0's abstention sentence covers judging blocking objections, not assigning status, so this is context, not a violation.
  - LC-11 says the KCC-1 header date is 2026-07-16. Confirmed. In addition, the `Created` header was only *added* to KCC-1 in #27 (2026-09-28). The original file `5a17429` had no `Created`.

### KR-14: Stale reference titles in KCC-2 and KCC-20 (not in the audit)

- **Severity:** info (new KCC editorial defect)
- **Evidence.** [K/kcc-0002.md#L289](https://github.com/kaspanet/kccs/blob/411b41bc14b3fda8f3a0548242c555f3597cad1a/kcc-0002.md#L289) and [K/kcc-0020.md#L293-L294](https://github.com/kaspanet/kccs/blob/411b41bc14b3fda8f3a0548242c555f3597cad1a/kcc-0020.md#L293-L294) title KCC-1 as "Covenant definition, concepts, bytes layout and ABI". That was the pre-#27 title. KCC-1 is now "Covenant Concepts, Byte Layouts, and ABI".
- **Recommendation.** Fold this into the LC-8 citation fix.

---

## Part B: verdict on each audit finding

| ID | Audit verdict | Review result | Notes |
| --- | --- | --- | --- |
| LC-1 | blocker | **Confirmed defect; consequence overstated** | `Status: Last Call` with no `Last-Call-Deadline` at [K/kcc-0001.md#L6](https://github.com/kaspanet/kccs/blob/411b41bc14b3fda8f3a0548242c555f3597cad1a/kcc-0001.md#L6) and [K/kcc-0002.md#L7](https://github.com/kaspanet/kccs/blob/411b41bc14b3fda8f3a0548242c555f3597cad1a/kcc-0002.md#L7). Header required per [K/kcc-0000.md#L154-L157](https://github.com/kaspanet/kccs/blob/411b41bc14b3fda8f3a0548242c555f3597cad1a/kcc-0000.md#L154-L157) and L276. #32/#33 merge times, SHAs and merger match. kccs.dev shows Last Call with no deadline string (fetched 2026-10-02). X post text and time match. **See KR-02** (the #25 precedent) and KR-03. |
| LC-2 | blocker | **Confirmed** | §4.3 text at [K/kcc-0000.md#L197-L204](https://github.com/kaspanet/kccs/blob/411b41bc14b3fda8f3a0548242c555f3597cad1a/kcc-0000.md#L197-L204). Status history: KCC-1 and KCC-2 go Draft→Last Call with no Review ([evidence/kccs-git-history.txt](evidence/kccs-git-history.txt)). That also skips the §4.2 flow (L135). Rendered §4.3 on kccs.dev still contains "retain their Draft". |
| LC-3 | blocker | **Confirmed** (all 10 items) | Item 1 (Draft, X replies verbatim): confirmed via the X API. Item 2 (header order/values): confirmed. Item 3: confirmed, minor line nit (KR-13). Item 4: `P2PKHHash` appears only at [K/kcc-0020.md#L164-L165](https://github.com/kaspanet/kccs/blob/411b41bc14b3fda8f3a0548242c555f3597cad1a/kcc-0020.md#L164-L165) and nowhere else in the repo. The keyed definition existed at `c0bb8f3` (kcc-0002.md L50-L53) and was removed by #30 `90beacd0`. Hashes reproduce. Item 5: section citations confirmed (KCC-1 §3.8.1 L675, §3.9 L709, §9 L1135). Item 6: confirmed; better framed as a KCC-2 defect (KR-04). Item 7: confirmed for `main`; #31 would settle the authority question (KR-08); the Argent reference follows the prose (KR-09). Item 8: unpinned KIP-20 link at L296 confirmed. Item 9: Argent master `76648f99` stub, PR #1 open at `5b2a2312`, updated 2026-10-02T13:45:06Z, all confirmed; tests now run (KR-09). Item 10: not re-verified line by line (Part C). |
| LC-4 | should-fix | **Confirmed** | Topic 141: 1 post (id 354, 2026-08-29T08:35:42Z). Topic 95: 4 posts, last id 355 (2026-08-29T09:05:46Z). Topic 8: `posts_count` 59, stream 61, last id 364 = post_number 73, Manyfest, `2026-09-11T10:50:15.762Z`. All exact ([evidence](evidence/)). Add KR-10. |
| LC-5 | should-fix | **Confirmed** | KCC-1 header order (Comments-URI at L11 after Requires). No RFC 2119 boilerplate anywhere in kcc-0001.md. First `MUST` at L137. KCC-2 boilerplate at L30-L34. |
| LC-6 | should-fix | **Confirmed** | Prose §6.8 = 44 bytes / 3 fields ([K/kcc-0001.md#L959-L981](https://github.com/kaspanet/kccs/blob/411b41bc14b3fda8f3a0548242c555f3597cad1a/kcc-0001.md#L959-L981)). JSON = 50 bytes / 4 fields incl. `label` (`conformance.json` L639-L667). Both recompute internally. Extra context: the JSON was added in #27 (`da834af`, 2026-09-28), whose squashed history includes "review: allow dynamic width field in state". The prose example predates it. So the JSON is the newer intent and the audit's primary fix (update the prose) is the right one. |
| LC-7 | should-fix | **Partly incorrect; downgrade to info** | See **KR-01**. |
| LC-8 | should-fix | **Confirmed** | "KCC-1 Section 3.1" (L90), "Section 7" (L110), "Section 11.2" (L225). The targets are as the audit says. The bytes next to them recompute. Also KR-14. |
| LC-9 | should-fix before Final | **Confirmed; understated for KCC-1** | KCC-0 Final gate (L166-L176), optional reference (L241-L244), KCC-2 snippets non-normative (L246-L250; `reference-code.md` L3-L4). 20 `approval_checks`, 11 with the `signature_valid` oracle: confirmed and now executed (KR-06). KCC-1 also has JSON-only vectors (**KR-05**). KCC-2 `Requires: KCC-1, KIP-20` (L11) and KIP-17/KIP-20 `Active` at `e4ae2332` (= kips master): confirmed. |
| LC-10 | should-fix | **Confirmed, with nuance** | See **KR-07**. KCC-1 §7.4 quote at L1113-L1124 confirmed. KCC-2 L102-L103 confirmed. KCC-20 L230, L247-L272 confirmed. |
| LC-11 | nit | **Confirmed** | KCC-20: Created 2026-07-15 vs added `e31a5a85` 2026-08-21T02:13:31+03:00; `Updated: 2026-08-25` vs last touch `3229efbb` 2026-08-28T11:35:42+03:00. KCC-1: 2026-07-16 vs added 2026-08-20 (`5a17429`). KCC-2: 2026-08-20 matches `502a8a2`. KCC-0: 2026-08-25 vs 2026-08-27, now confirmed (KR-03). |
| LC-12 | holds | **Confirmed and extended** | Every value listed recomputes with two BLAKE3 implementations plus hashlib BLAKE2b (KR-06). KIP-17 "Covenants and Improved Scripting Capabilities", Active, Updated 2026-05-31; KIP-20 "Covenant IDs", Active, Updated 2026-05-28, both at `e4ae2332`, which is still `kaspanet/kips` master (committed 2026-07-15T12:19:57Z). |

**Other audit files**

- **"Judged and left as holds"** ([A/AUDIT.md#L216-L225](https://github.com/STP-KAS/kcc-last-call-audit-2026-10-02/blob/9c9c133b2cfd66e7236085ad02fab343bc62b238/AUDIT.md#L216-L225)): confirmed.
  - KCC-1 §7.5 is `N/A` (L1128).
  - KCC-2 Security Considerations at L252.
  - #24, #26 and #29 touch only `kcc-0012*`, `kcc-0023*` and `kcc-0003/4/5.md` (plus README).
  - Issues #14 and #28 are open.
  - Repo collaborators/editors cannot be listed without push access (HTTP 403). The audit's "did not claim a head count" was the right call.
- **INCONSISTENCIES.md:** consistent with AUDIT.md. Every row checked against the same sources above. The LC-7 row inherits KR-01.
- **MASTER-DELTA.md: confirmed.** STP-KAS/kaspa-master-file `main` is still `99ae9620dd580ff0630cd720f83a0e78de616f4e` at review time. README L62 and `master.json` L81 still pin argent PR #1 head `60064687` (27 Sep). The live head is `5b2a2312`. The KCC row already records the missing deadline, as the audit says.
- **COVERAGE.md / SECOND-PASS.md:** the coverage statements are honest. The three X posts were re-read here through the X API and match the quoted text and times. kccs.dev re-fetched (index, KCC-0/1/2/20 pages):
  - no `Last-Call-Deadline` on the KCC-1/KCC-2 pages;
  - "retain their Draft" present on the KCC-0 page;
  - `P2PKHHash` present twice on the KCC-20 page;
  - "KCC-1 Section 3.1" present on the KCC-2 page.
- **Fabrication check:** no invented SHA, timestamp, line number, quote or hash was found. Every SHA quoted in the audit resolves in the relevant repo.

---

## Part C: could not be verified

- **LC-3 item 10** (the July opening post of Kas-Smiths topic 8 "describes a different ABI"). The topic JSON was fetched ([evidence](evidence/kas-smiths-t_8.json)), but the opening post was not compared field by field with the merged ABI. Not confirmed, not refuted.
- **kaspaexplained `/status`.** Not fetched. Neither the audit nor this review relies on it.
- **kccs.dev full HTML diff** against the raw markdown. Only targeted strings were checked.
- **Who the KCC editors are.** KCC-0 §12 defines them as the repo maintainers by access settings, and the collaborators API needs push access (HTTP 403). Whether "more than one editor exists" (the §12.1 abstention trigger) is unverified.
- **Review-comment threads on #27, #30, #32, #33** beyond reviews and top-level comments. #32-#34 have no comments and one approval each. #27/#30 inline threads were not read.
- **Whether #31's reject rows equal closed #20.** Not compared. The #31 git log shows a merge of a branch named `pr-1-shawn-reject-vectors`, and #20 was opened by ShawnPearce, which suggests overlap. Not verified.
- **Silverscript compiler `blake3` / `checkSigECDSA` bodies.** Not opened.
- **Teammate input.** This worker had no channel to the "kaspa master challenge" or "kaspa master bot" agents (no agent-messaging tool was available in this session). The challenger's own copy of the master file (a private STP-KAS repository, not named here; last pushed 2026-09-29) was read. It predates the 1 Oct status change and adds nothing that contradicts the audit.

## Part D: open questions

1. Will the editors close the KCC-1/KCC-2 Last Call on about 2026-10-15 (the #25 counting), on 2026-10-16 (the X post counting), or only after a `Last-Call-Deadline` header is set? (KR-02)
2. Do the editors read KCC-2 §2.1 L83-84 as allowing `byte[32]` for `p2pk-schnorr/v1` values in a multi-scheme field? (KR-04)
3. Is a KCC-20 Last Call meant to require a merged reference first, as the @kccforum reply says, although KCC-0 makes the reference a Final gate only? (audit LC-3)
4. Will the KCC-1 Comments-URI questions in post 354 be answered on the thread before Last Call closes? (KR-10)
5. Will a KCC-20 version restrict the borrow-signature sighash type, given the reference deliberately accepts all six? (KR-07)

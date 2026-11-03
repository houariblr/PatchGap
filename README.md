# patchgap

Finds Solidity files that still contain a known pre-patch snippet.
Illustrative examples in `examples/` are synthetic, not real advisories.

    cargo build --release
    ./target/release/patchgap --old examples/old.sol --new examples/new.sol --all examples/targets

Verdicts: UNPATCHED, PATCHED, AMBIGUOUS, NO_MATCH. Exit code 1 when anything is UNPATCHED.

Two stages per file
1. exact: the old or new snippet is searched character for character after removing only comments and layout.
   A hit here cannot be a false positive. Snippets under 40 canonical characters skip this stage.
2. fuzzy: if stage one settles nothing, token shingles are compared (renamed variables still match).
   Treat fuzzy hits as leads and confirm them by hand.
The tier shows in the output next to each verdict.

Fuzzy stage details
- Guards are unified before comparison: `require(c, "m")`, `if (!c) revert E();` and `if (!c) { revert E(); }` become one shape (normalized mode only; `--exact` and the exact stage are untouched).
- Evidence is scored per candidate region (a window of 2x the snippet length), not over the whole file, so large flattened contracts do not pollute the counts and a file holding a fixed and an unfixed copy is judged copy by copy: one vulnerable copy makes the file UNPATCHED, PATCHED needs every copy fixed. An exact hit on the fixed code is therefore not final.
- UNPATCHED also fires by margin (old >= 0.5 and old - new >= 0.5). PATCHED keeps the strict thresholds on purpose: a wrong PATCHED hides a vulnerable file.
- Known limits: renamed aliases (`proofLen` vs `proof.length`) and rewritten functions stay AMBIGUOUS or NO_MATCH; numeric literals are normalized except the ones the fix adds or removes (`>= 20`, a removed `64` branch); a partial fix that drops one token out of a multi-hunk patch can still score PATCHED; variables named like a lexer keyword (`data`, `sender`, `value`) are not normalized when renamed; OpenZeppelin 5.x rewrote several of these functions, so a snippet pair per code generation is needed.

Measuring: see `bench/README.md`.

Notes
- Token shingles, no parsing: formatting, comments and (by default) renamed variables do not matter.
- Short or very common snippets raise false positives. Check every hit by hand.
- Use only to report findings to owners or through bounty programs that cover them.

## Results

Measured with the labelled benchmark in `bench/` (Precision/Recall/FPR per verdict). Held-out split: OpenZeppelin
`UUPSUpgradeable` (fixed 4.3.2), 160 cases, generated and frozen before the engine was final (hash in `bench/FROZEN.json`).

| | first version | current |
|---|---|---|
| correct verdicts | 108 / 160 | 122 / 160 |
| vulnerable files missed (reported patched or no-match) | 4 of 45 | 0 of 45 |
| false UNPATCHED | 0 | 0 |
| wrong PATCHED (the costly error) | 5 | 1 |

The 38 remaining misses: 35 fixed files reported NO_MATCH (the fix is written differently from the snippet pair), 2 near-miss
"fixes" reported NO_MATCH, and 1 near-miss "fix" (v4.9.6) reported PATCHED.
Dev splits with the current engine: ECDSA 185/186, MerkleProof 156/190, ERC2771Context 136/170, with no PATCHED on a vulnerable or near-miss file.

Limits, stated plainly: four OpenZeppelin patches only; derived cases come from a few base files and are correlated;
one near-miss "fix" is still reported PATCHED on the held-out split; no manually labelled corpus of deployed contracts yet.
A `UNPATCHED` verdict from the exact stage is reliable; everything else is a lead to confirm by hand.

## Validation on a real patch (OpenZeppelin ECDSA, GHSA-4h98-2769-gh6h)

`examples/oz-ecdsa/` holds the real pre/post-fix `tryRecover(bytes32,bytes)` from commit d693d89 (fixed in v4.7.3)
and the `ECDSA.sol` of 47 release tags. Ground truth: v4.1.0 up to v4.7.2 are affected, v4.7.3 and later are fixed.

    python3 -I examples/oz-ecdsa/eval.py ./target/release/patchgap \
        examples/oz-ecdsa/old.sol examples/oz-ecdsa/new.sol examples/oz-ecdsa/targets 6

Result: 46 of 47 correct; 24 of the 47 were settled by the exact stage alone. The miss is v4.1.0, whose older implementation differs from the
patched function, so it falls below the context threshold (a false negative).
This is a best case: clean release files with consistent formatting. Flattened or edited copies
inside real deployed contracts will score lower. Measure on a real corpus before trusting it.

## Scanning real contracts

    python tools/fetch_sourcify.py --chain 1 --count 500 --out corpus
    python tools/scan.py corpus

`fetch_sourcify.py` downloads verified sources from Sourcify (API v2), one request
at a time with a pause, and resumes on rerun. `scan.py` runs every bundled patch
and writes `report.txt`. Treat `exact` hits as findings to verify by hand and
`fuzzy` hits as leads. Report to the contract owner or a bounty program only.

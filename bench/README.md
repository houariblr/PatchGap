# patchgap benchmark

Labelled cases for measuring the matcher honestly: Precision / Recall / FPR **per verdict**, not accuracy alone.

    python bench/fetch_data.py                  # also downloads the AGPL Solmate file, which is not committed
    python bench/make_cases.py                  # regenerate bench/cases (deterministic; needs corpus/ for the host contracts)
    cargo build --release
    python bench/metrics.py                     # dev split: ECDSA + MerkleProof
    python bench/metrics.py --out bench/results/x.json --compare bench/results/step4.json --show-wrong

On Windows PowerShell use `python` (not `python3`) and, if the binary is elsewhere, `--exe .\target\release\patchgap.exe`.

## Splits and the no-peeking rule
- **dev** = ECDSA (`tryRecover`, fixed 4.7.3), MerkleProof (`processMultiProof`, fixed 4.9.2) and ERC2771Context
  (`_msgSender`/`_msgData`, fixed 4.9.3). Merkle's failures motivated the guard-unification and margin steps; ERC2771 was
  the first unseen split and became dev once the literal-sensitivity step was tuned against it.
- **test** = UUPSUpgradeable (`onlyProxy`, fixed 4.3.2): 4 vulnerable and 33 fixed tags. Chosen and generated before the
  literal step and never run on any engine until it was frozen: `metrics.py --freeze` stores the sha256 of `src/*.rs` in
  `FROZEN.json`; `--split test` refuses to run if `src/` differs. Any engine change after the first test run makes it a
  dev split again: pick a 5th patch then. `bench/results/` keeps every run (baseline, step2-4, literal, uups_*).

**Amendment (see `FROZEN.json`):** after the test split was first run, the verdict labels were renamed (`patched` -> `PATCHED`, `ambiguous` -> `AMBIGUOUS`, `no-match` -> `NO_MATCH`). Matching code did not change; the old and new binaries give byte-identical scores on 177 output lines once the spelling is mapped. The freeze hash was refreshed for that reason only; `metrics.py` still reads both spellings.

## Labels (the verdicts that count as correct)
| label | correct verdicts |
|---|---|
| UNPATCHED | UNPATCHED |
| PATCHED | PATCHED |
| NO_MATCH | NO_MATCH (similar-looking but unrelated code, or a real contract without the patched region) |
| NOT_AFFECTED | anything but UNPATCHED (version that never had the bug) |
| NOT_PATCHED | UNPATCHED or AMBIGUOUS (near-miss "fix"; must never be PATCHED) |

AMBIGUOUS is an abstention, never the single right answer, so it has no recall; its FPR column is the abstention rate.
Labels describe **code lineage** (is this the pre-patch OpenZeppelin code?), not abstract vulnerability: Solady's ECDSA
accepts malleable signatures too but is NO_MATCH here.

## Categories
real_tag (release files, ground truth by version) · rename · format (comments/layout) · independent (unrelated edits
next to the fix) · merged_S/M/L (inside a real contract of ~3 KB / ~20 KB / ~100 KB) · dual_copy (a fixed and an unfixed
copy in one file: UNPATCHED) · near_miss (weaker "fix") · negative_similar (Solady, Solmate, Permit2, other OZ files)
· host_S/M/L (real contracts alone).

## Caveats
- Derived cases come from 8 base files per patch, so they are correlated: read per-category counts as "does this family
  of transformations break the engine", not as independent samples. Equal weight per family also over-weights the two
  hard Merkle families (4.7/4.8 and 5.x) compared with how often they occur in the wild.
- Solmate has no ECDSA library, so ECDSA negatives are Solady, Permit2, Solmate ERC20 (ecrecover) and OZ files.
- `bench/data/` holds third-party files (see MANIFEST.tsv). `bench/cases/` contains real contracts used as hosts: it is
  regenerable, so do not publish it if the repo goes public.

#!/usr/bin/env python3
"""Run patchgap with every known patch over a downloaded corpus.

  python tools/scan.py corpus

Writes report.txt: one section per patch, UNPATCHED first (exact before fuzzy).
Only 'exact' lines are reliable; 'fuzzy' lines are leads to open and read.
"""
import os, subprocess, sys
corpus = sys.argv[1] if len(sys.argv) > 1 else "corpus"
exe = os.path.join("target", "release", "patchgap.exe" if os.name == "nt" else "patchgap")
patches = [
    ("OZ ECDSA signature malleability (CVE-2022-35961), fixed 4.7.3", "examples/oz-ecdsa/old.sol", "examples/oz-ecdsa/new.sol"),
    ("OZ MerkleProof multiproof (CVE-2023-34459), fixed 4.9.2", "examples/oz-merkle/old.sol", "examples/oz-merkle/new.sol"),
]
with open("report.txt", "w", encoding="utf-8") as rep:
    for name, old, new in patches:
        r = subprocess.run([exe, "--old", old, "--new", new, corpus], capture_output=True, text=True)
        lines = [l for l in r.stdout.splitlines() if l.startswith(("UNPATCHED", "AMBIGUOUS"))]
        rep.write(f"## {name}\n{r.stderr.strip()}\n" + "\n".join(lines) + "\n\n")
        print(name, "->", r.stderr.strip())
print("wrote report.txt")

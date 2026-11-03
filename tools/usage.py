#!/usr/bin/env python3
"""For each flagged file in report.txt, show whether the rest of that contract
actually calls the vulnerable library function. A vulnerable copy that is never
called is not a vulnerability.

  python tools/usage.py report.txt
"""
import os, re, sys
rules = {
    "ECDSA": re.compile(r"\b(ECDSA\.)?(tryRecover|recover)\s*\("),
    "MerkleProof": re.compile(r"\b(multiProofVerify|processMultiProof)(Calldata)?\s*\("),
}
section = None
for line in open(sys.argv[1] if len(sys.argv) > 1 else "report.txt", encoding="utf-8"):
    line = line.rstrip("\n")
    if line.startswith("## "):
        section = "ECDSA" if "ECDSA" in line else "MerkleProof"; print("\n" + line); continue
    m = re.match(r"(UNPATCHED|AMBIGUOUS)\s+(exact|fuzzy)\s+\S+\s+\S+\s+\S+\s+(.*)$", line)
    if not m or not section: continue
    verdict, tier, path = m.groups()
    path = path.replace("\\", os.sep)
    parts = path.split(os.sep)
    if len(parts) < 3: continue
    root = os.sep.join(parts[:3])  # corpus/<chain>/<address>
    hits = []
    for d, _, files in os.walk(root):
        for f in files:
            p = os.path.join(d, f)
            if not f.endswith(".sol") or os.path.abspath(p) == os.path.abspath(path): continue
            try: text = open(p, encoding="utf-8", errors="ignore").read()
            except OSError: continue
            for n, l in enumerate(text.splitlines(), 1):
                if rules[section].search(l) and not l.strip().startswith(("//", "*", "function ")):
                    hits.append((os.path.relpath(p, root), n, l.strip()[:110]))
    print(f"{verdict:<9} {tier:<5} {parts[2]}  ->", "USED" if hits else "not called")
    for h in hits[:5]: print(f"      {h[0]}:{h[1]}  {h[2]}")

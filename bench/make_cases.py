#!/usr/bin/env python3
"""Generate the labelled benchmark cases for patchgap.

  python bench/make_cases.py          # (re)creates bench/cases/** and bench/labels.tsv

Deterministic (fixed seed). It never runs patchgap and the cases are written
before any engine change, so the labels cannot be tuned to the engine.

Labels (what a correct tool may answer; see bench/README.md):
  UNPATCHED     -> UNPATCHED        PATCHED   -> PATCHED       NO_MATCH -> NO_MATCH
  NOT_AFFECTED  -> anything but UNPATCHED (related code that never had the bug)
  NOT_PATCHED   -> UNPATCHED or AMBIGUOUS (a near-miss "fix": must never be PATCHED)

Splits: dev = ECDSA + MerkleProof, test = ERC2771Context (not to be run until the
engine is frozen, see metrics.py --freeze).
"""
import hashlib, os, random, re, shutil, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "bench"
CASES = BENCH / "cases"
CORPUS = ROOT / "corpus"
SEED = 20261102


def ver(tag):
    return tuple(int(x) for x in re.findall(r"\d+", tag)[:3])


def truth_ecdsa(v):
    return "PATCHED" if v >= (4, 7, 3) else "UNPATCHED" if v >= (4, 1, 0) else "NOT_AFFECTED"


def truth_merkle(v):
    return "PATCHED" if v >= (4, 9, 2) else "UNPATCHED" if v >= (4, 7, 0) else "NOT_AFFECTED"


def truth_erc2771(v):
    return "PATCHED" if v >= (4, 9, 3) else "UNPATCHED"


def truth_uups(v):
    return "PATCHED" if v >= (4, 3, 2) else "UNPATCHED"


# Bases for the derived cases: chosen by spreading over the version grid (and over the
# syntactic families: old layout, `unchecked`, `if/revert`), before any engine run.
PATCHES = {
    "ecdsa": dict(
        split="dev", dir=ROOT / "examples" / "oz-ecdsa", prefix="ECDSA", truth=truth_ecdsa,
        bases=["v4.3.0", "v4.5.0", "v4.7.0", "v4.7.2", "v4.7.3", "v4.9.6", "v5.0.0", "v5.7.0"],
        decl=r"library ECDSA\b", decl_to="library ECDSA2",
        rename={"hash": "digest", "signature": "sig", "r": "rr", "s": "ss", "v": "vv", "vs": "vsh"},
        header=r"function\s+(?:try)?[rR]ecover\s*\(\s*bytes32\s+hash\s*,\s*bytes\s+memory\s+signature\s*\)[^{]*\{",
        probe="uint256 __len = signature.length;",
    ),
    "merkle": dict(
        split="dev", dir=ROOT / "examples" / "oz-merkle", prefix="MerkleProof", truth=truth_merkle,
        bases=["v4.7.0", "v4.8.0", "v4.9.0", "v4.9.1", "v4.9.2", "v4.9.6", "v5.0.0", "v5.7.0"],
        decl=r"library MerkleProof\b", decl_to="library MerkleProof2",
        rename={"proof": "siblings", "proofFlags": "flags", "leaves": "items", "leavesLen": "nLeaves",
                "proofLen": "nProof", "totalHashes": "nHashes", "hashes": "acc", "leafPos": "li",
                "hashPos": "hi", "proofPos": "pi", "merkleRoot": "rootOut",
                "processMultiProof": "rebuildRoot", "processMultiProofCalldata": "rebuildRootCd"},
        header=r"function\s+processMultiProof\s*\([^)]*\)[^{]*\{",
        probe="uint256 __n = proof.length;",
    ),
    "erc2771": dict(
        split="dev", dir=ROOT / "examples" / "oz-erc2771", prefix="ERC2771Context", truth=truth_erc2771,
        bases=["v4.0.0", "v4.5.0", "v4.9.0", "v4.9.2", "v4.9.3", "v5.0.0", "v5.2.0", "v5.7.0"],
        decl=r"abstract contract ERC2771Context\b", decl_to="abstract contract ERC2771Context2",
        rename={"sender": "caller_", "forwarder": "fwd", "_trustedForwarder": "_tfwd",
                "trustedForwarder": "tfwdArg", "isTrustedForwarder": "isForwarder"},
        header=r"function\s+_msgSender\s*\(\s*\)[^{]*\{",
        probe="uint256 __cd = msg.data.length;",
    ),
    # 4th patch, added after the first test split was spent (ERC2771 became dev when the
    # literal-sensitivity step was made). Not run on any engine until that engine is frozen.
    "uups": dict(
        split="test", dir=ROOT / "examples" / "oz-uups", prefix="UUPSUpgradeable", truth=truth_uups,
        bases=["v4.1.0", "v4.2.0", "v4.3.0", "v4.3.1", "v4.3.2", "v4.9.6", "v5.0.0", "v5.7.0"],
        decl=r"abstract contract UUPSUpgradeable\b", decl_to="abstract contract UUPSUpgradeable2",
        rename={"newImplementation": "impl_", "data": "payload", "__self": "__me", "onlyProxy": "onlyThroughProxy",
                "upgradeTo": "upgradeImpl", "upgradeToAndCall": "upgradeImplAndCall"},
        header=r"function\s+upgradeToAndCall\s*\([^)]*\)[^{]*\{",
        probe="uint256 __g = 0;",
    ),
}

EXCLUDE_UUPS = re.compile(r"UUPSUpgradeable|onlyProxy|upgradeToAndCall", re.I)
EXCLUDE_HOST = re.compile(
    r"processMultiProof|MerkleProof|multiProofVerify|verifyMultiProof|tryRecover|ECDSA|ERC2771|"
    r"isTrustedForwarder|_trustedForwarder|MinimalForwarder", re.I)


# ---------- text transforms -------------------------------------------------------------
def rename_ids(text, mapping):
    for old, new in sorted(mapping.items(), key=lambda kv: -len(kv[0])):
        text = re.sub(r"(?<![\w.$])" + re.escape(old) + r"(?![\w$])", new, text)
    return text


TOK = re.compile(
    r"//[^\n]*|/\*.*?\*/|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[A-Za-z_$][A-Za-z0-9_$]*|\d[\w.]*|"
    r"==|!=|<=|>=|&&|\|\||\+\+|--|\+=|-=|\*=|/=|%=|\*\*|<<|>>|=>|->|&=|\|=|\S", re.S)


def relayout(text, style, rng):
    toks = [t for t in TOK.findall(text) if not t.startswith(("//", "/*"))]
    out, line, depth, n = [], [], 0, 0
    for t in toks:
        line.append(t)
        if t in (";", "{", "}"):
            if t == "}":
                depth = max(0, depth - 1)
            if style == "compact":
                out.append(" ".join(line))
            else:
                n += 1
                pad = " " * rng.choice([0, 2, 4, 8]) if rng.random() < 0.7 else "\t" * rng.randint(0, 3)
                note = rng.choice(["", "", " // note %d" % n, " /* review %d */" % n])
                if rng.random() < 0.25:
                    out.append("")
                out.append(pad + " ".join(line) + note)
            line = []
            if t == "{":
                depth += 1
    if line:
        out.append(" ".join(line))
    return "\n".join(out) + "\n"


def ind_insert(text, spec):
    new, n = re.subn(spec["header"], lambda m: m.group(0) + " " + spec["probe"], text)
    return new if n else None


def ind_visibility(text, spec):
    m = re.search(spec["header"], text)
    if not m:
        return None
    head = m.group(0)
    if " internal " not in head:
        return None
    return text.replace(head, head.replace(" internal ", " public ", 1), 1)


def ind_text(patch):
    def f(text, spec):
        if patch == "merkle":
            t = text.replace("MerkleProof: invalid multiproof", "bad multiproof")
            t = re.sub(r"\bMerkleProofInvalidMultiproof\b", "BadMultiproof", t)
            return t if t != text else None
        if patch == "ecdsa":
            t = re.sub(r"\bInvalidSignatureLength\b", "BadLength", text)
            return t if t != text else None
        if patch == "uups":
            t = text.replace("Function must be called through delegatecall", "bad context")
            t = t.replace("Function must be called through active proxy", "bad proxy")
            t = re.sub(r"\bUUPSUnauthorizedCallContext\b", "BadContext", t)
            return t if t != text else None
        return None
    return f


def ind_swap(patch):
    def f(text, spec):
        if patch == "ecdsa":
            t, n = re.subn(r"(bytes32 r;)(\s*)(bytes32 s;)", r"\3\2\1", text)
            return t if n else None
        if patch == "merkle":
            t, n = re.subn(r"(uint256 leafPos = 0;)(\s*)(uint256 hashPos = 0;)", r"\3\2\1", text)
            return t if n else None
        if patch in ("erc2771", "uups"):
            a, b = ("_msgSender", "_msgData") if patch == "erc2771" else ("upgradeTo", "upgradeToAndCall")
            m = re.search(r"(\n[^\n]*function " + a + r"\(.*?\n    \})(\s*)(\n[^\n]*function " + b + r"\(.*?\n    \})",
                          text, re.S)
            if not m:
                return None
            return text[:m.start()] + m.group(3) + m.group(2) + m.group(1) + text[m.end():]
        return None
    return f


def near_miss(patch, text):
    """A 'fix' that keeps the shape but is weaker/wrong. Never to be reported PATCHED."""
    subs = {
        "merkle": [(r"proofPos == proofLen", "proofPos <= proofLen"),
                   (r"proofPos != proofLen", "proofPos > proofLen"),
                   (r"proofPos != proof\.length", "proofPos > proof.length")],
        "erc2771": [(r"msg\.data\.length >= 20", "msg.data.length >= 1"),
                    (r"calldataLength >= contextSuffixLength", "calldataLength >= 1")],
    }.get(patch, [])
    if patch == "uups":  # partial fix: upgradeToAndCall left unprotected
        out, n = re.subn(r"(function\s+upgradeToAndCall\([^)]*\)[^{]*?)\s+onlyProxy\b", r"\1", text, count=1)
        return out if n else None
    out, hit = text, False
    for pat, rep in subs:
        out, n = re.subn(pat, rep, out)
        hit = hit or bool(n)
    return out if hit else None


# ---------- file helpers --------------------------------------------------------------
def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def read(path):
    return Path(path).read_text(encoding="utf-8")


def pick_hosts(rng):
    pool = []
    for p in sorted(CORPUS.rglob("*.sol")):
        try:
            t = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if EXCLUDE_HOST.search(t) or len(t) > 135_000:
            continue
        pool.append(t)
    bins = {"S": (1_500, 6_000, 10), "M": (12_000, 30_000, 10), "L": (60_000, 135_000, 6)}
    hosts = {}
    for k, (lo, hi, n) in bins.items():
        c = [t for t in pool if lo <= len(t) <= hi]
        rng.shuffle(c)
        hosts[k] = c[:n]
    return hosts


def main():
    if CASES.exists():
        shutil.rmtree(CASES)
    rng = random.Random(SEED)
    hosts = pick_hosts(rng)
    rows = []  # patch, split, id, category, label, note

    def emit(patch, spec, cid, cat, label, text, note=""):
        write(CASES / patch / f"{cid}.sol", text)
        rows.append((patch, spec["split"], cid, cat, label, note))

    neg_files = sorted((BENCH / "data" / "neg").glob("*.sol"))
    for patch, spec in PATCHES.items():
        # hosts that themselves contain UUPS code are not negatives for the UUPS patch
        hosts_p = ({k: [h for h in v if not EXCLUDE_UUPS.search(h)] for k, v in hosts.items()}
                   if patch == "uups" else hosts)
        targets = sorted((spec["dir"] / "targets").glob("*.sol"), key=lambda p: ver(p.stem))
        real = {re.search(r"v[\d.]+", p.stem).group(): read(p) for p in targets}
        labels = {t: spec["truth"](ver(t)) for t in real}
        for t, txt in real.items():
            emit(patch, spec, f"real__{t}", "real_tag", labels[t], txt)
        bases = [b for b in spec["bases"] if b in real]
        for b in bases:
            lab, txt = labels[b], real[b]
            # 1. renamed identifiers
            emit(patch, spec, f"rename__{b}", "rename", lab, rename_ids(txt, spec["rename"]))
            # 2. other layout / comments
            for st in ("compact", "noisy"):
                emit(patch, spec, f"format_{st}__{b}", "format", lab, relayout(txt, st, rng))
            # 3. independent edits next to the fix
            for name, fn in (("probe", ind_insert), ("visibility", ind_visibility),
                             ("text", ind_text(patch)), ("swap", ind_swap(patch))):
                out = fn(txt, spec)
                if out and out != txt:
                    emit(patch, spec, f"indep_{name}__{b}", "independent", lab, out)
            # 3b. several independent edits at once, plus rename and layout
            combo = ind_insert(txt, spec) or txt
            combo = rename_ids(combo, spec["rename"])
            emit(patch, spec, f"combo__{b}", "independent", lab, relayout(combo, "noisy", rng),
                 "probe+rename+layout")
            # 4. merged into a larger contract (flattened file), three host sizes
            for size in ("S", "M", "L"):
                host = rng.choice(hosts_p[size])
                host2 = rng.choice(hosts_p["S"])
                pos = rng.choice(["after", "before", "between"])
                body = rename_ids(txt, spec["rename"]) if rng.random() < 0.5 else txt
                if pos == "after":
                    merged = host + "\n" + body
                elif pos == "before":
                    merged = body + "\n" + host
                else:
                    merged = host2 + "\n" + body + "\n" + host
                emit(patch, spec, f"merged_{size}__{b}", f"merged_{size}", lab, merged, pos)
        # 5. two copies in one file: any vulnerable copy left => UNPATCHED
        unp = [b for b in bases if labels[b] == "UNPATCHED"]
        pat = [b for b in bases if labels[b] == "PATCHED"]
        k = 0
        for u in unp:
            for p in pat[:2]:
                a, b2 = (real[u], real[p]) if k % 2 == 0 else (real[p], real[u])
                second = re.sub(spec["decl"], spec["decl_to"], b2, count=1)
                emit(patch, spec, f"dual__{u}_{p}", "dual_copy", "UNPATCHED", a + "\n" + second,
                     "unpatched+patched copies")
                k += 1
        for i, (p1, p2) in enumerate(zip(pat, pat[1:])):
            second = re.sub(spec["decl"], spec["decl_to"], real[p2], count=1)
            emit(patch, spec, f"dual__{p1}_{p2}", "dual_copy", "PATCHED", real[p1] + "\n" + second,
                 "two patched copies")
        # 6. near-miss fixes (must not be PATCHED)
        for p in pat:
            nm = near_miss(patch, real[p])
            if nm:
                emit(patch, spec, f"nearmiss__{p}", "near_miss", "NOT_PATCHED", nm)
        # 7. negatives: similar-looking but unrelated code, and large real contracts alone
        for nf in neg_files:
            emit(patch, spec, f"neg__{nf.stem}", "negative_similar", "NO_MATCH", read(nf), "similar, unrelated")
        for size, lst in hosts_p.items():
            for i, h in enumerate(lst):
                emit(patch, spec, f"host_{size}{i:02d}", f"host_{size}", "NO_MATCH", h, "unrelated real contract")

    with open(BENCH / "labels.tsv", "w", encoding="utf-8", newline="\n") as f:
        f.write("patch\tsplit\tid\tcategory\tlabel\tnote\n")
        for r in rows:
            f.write("\t".join(r) + "\n")
    from collections import Counter
    for patch in PATCHES:
        c = Counter((r[3]) for r in rows if r[0] == patch)
        print(patch, sum(c.values()), dict(sorted(c.items())))
    print("labels:", Counter(r[4] for r in rows))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Score patchgap on the labelled benchmark: Precision / Recall / FPR per verdict.

  python bench/metrics.py                         # dev split (ECDSA + MerkleProof)
  python bench/metrics.py --out bench/results/after_step2.json --compare bench/results/baseline.json
  python bench/metrics.py --freeze                # record the engine hash; do this ONCE, before the test split
  python bench/metrics.py --split test            # held-out ERC2771Context; refuses if src/ changed after --freeze

Label semantics (the set of verdicts that count as correct for a case):
  UNPATCHED {UNPATCHED}   PATCHED {PATCHED}   NO_MATCH {NO_MATCH}
  NOT_AFFECTED {NO_MATCH, PATCHED, AMBIGUOUS}   NOT_PATCHED {UNPATCHED, AMBIGUOUS}
AMBIGUOUS is an abstention: it is never the single correct answer, so its "recall" is
undefined and its FPR column is the abstention rate on cases that had a decidable answer.
"""
import argparse, collections, hashlib, json, os, re, subprocess, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "bench"
VERDICTS = ["UNPATCHED", "PATCHED", "AMBIGUOUS", "NO_MATCH"]
ALLOWED = {
    "UNPATCHED": {"UNPATCHED"}, "PATCHED": {"PATCHED"}, "NO_MATCH": {"NO_MATCH"},
    "NOT_AFFECTED": {"NO_MATCH", "PATCHED", "AMBIGUOUS"}, "NOT_PATCHED": {"UNPATCHED", "AMBIGUOUS"},
}
PATCHDIR = {"ecdsa": "oz-ecdsa", "merkle": "oz-merkle", "erc2771": "oz-erc2771", "uups": "oz-uups"}
SPLIT = {"ecdsa": "dev", "merkle": "dev", "erc2771": "dev", "uups": "test"}
LINE = re.compile(r"^(UNPATCHED|patched|ambiguous|no-match)\s+(exact|fuzzy)\s+ctx=([\d.]+) old=([\d.]+) new=([\d.]+)\s+(.+)$",
                  re.I)
NAME = {"unpatched": "UNPATCHED", "patched": "PATCHED", "ambiguous": "AMBIGUOUS", "no-match": "NO_MATCH"}


def src_hash():
    h = hashlib.sha256()
    for p in sorted((ROOT / "src").glob("*.rs")):
        h.update(p.name.encode() + b"\0" + p.read_bytes().replace(b"\r\n", b"\n") + b"\0")
    return h.hexdigest()


def find_exe(arg):
    if arg:
        return arg
    names = ["patchgap.exe", "patchgap"] if os.name == "nt" else ["patchgap"]
    roots = [Path(os.environ["CARGO_TARGET_DIR"])] if os.environ.get("CARGO_TARGET_DIR") else []
    roots.append(ROOT / "target")
    for r in roots:
        for n in names:
            if (r / "release" / n).exists():
                return str(r / "release" / n)
    sys.exit("patchgap binary not found: run `cargo build --release` or pass --exe")


def labels():
    rows = {}
    for i, line in enumerate((BENCH / "labels.tsv").read_text(encoding="utf-8").splitlines()):
        if i == 0 or not line.strip():
            continue
        patch, split, cid, cat, label, note = (line.split("\t") + [""])[:6]
        rows[(patch, cid)] = dict(patch=patch, split=split, id=cid, category=cat, label=label)
    return rows


def run(exe, patch, extra):
    d = ROOT / "examples" / PATCHDIR[patch]
    cmd = [exe, "--old", str(d / "old.sol"), "--new", str(d / "new.sol"), "--all", *extra,
           str(BENCH / "cases" / patch)]
    out = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    got = {}
    for line in out.stdout.splitlines():
        m = LINE.match(line.strip())
        if not m:
            continue
        v, tier, ctx, old, new, path = m.groups()
        got[Path(path).stem] = dict(verdict=NAME[v.lower()], tier=tier, ctx=float(ctx), old=float(old), new=float(new))
    return got


def ratio(a, b):
    return None if b == 0 else a / b


def prf(rows):
    res = {}
    for v in VERDICTS:
        tp = sum(1 for r in rows if r["verdict"] == v and v in ALLOWED[r["label"]])
        fp = sum(1 for r in rows if r["verdict"] == v and v not in ALLOWED[r["label"]])
        fn = sum(1 for r in rows if r["verdict"] != v and ALLOWED[r["label"]] == {v})
        tn = sum(1 for r in rows if r["verdict"] != v and v not in ALLOWED[r["label"]])
        res[v] = dict(tp=tp, fp=fp, fn=fn, tn=tn, precision=ratio(tp, tp + fp),
                      recall=None if v == "AMBIGUOUS" else ratio(tp, tp + fn), fpr=ratio(fp, fp + tn))
    return res


def critical(rows):
    fa = [r for r in rows if r["verdict"] == "PATCHED" and r["label"] in ("UNPATCHED", "NOT_PATCHED")]
    fa_den = sum(1 for r in rows if r["label"] in ("UNPATCHED", "NOT_PATCHED"))
    al = [r for r in rows if r["verdict"] == "UNPATCHED" and "UNPATCHED" not in ALLOWED[r["label"]]]
    al_den = sum(1 for r in rows if "UNPATCHED" not in ALLOWED[r["label"]])
    neg = [r for r in rows if r["label"] == "NO_MATCH"]
    neg_al = [r for r in neg if r["verdict"] == "UNPATCHED"]
    fz = [r for r in rows if r["verdict"] == "UNPATCHED" and r["tier"] == "fuzzy"]
    fz_ok = [r for r in fz if "UNPATCHED" in ALLOWED[r["label"]]]
    return dict(false_assurance=(len(fa), fa_den), false_alarm=(len(al), al_den),
                false_alarm_on_unrelated=(len(neg_al), len(neg)), fuzzy_unpatched_precision=(len(fz_ok), len(fz)))


def outcome(r):
    if r["verdict"] in ALLOWED[r["label"]]:
        return "correct"
    return "abstain" if r["verdict"] == "AMBIGUOUS" else "wrong"


def pct(x):
    return "  n/a" if x is None else f"{100 * x:5.1f}"


def report(title, rows):
    print(f"\n### {title}  (n={len(rows)})")
    m = prf(rows)
    print(f"{'verdict':<10} {'TP':>4} {'FP':>4} {'FN':>4} {'TN':>4} | {'Prec%':>6} {'Rec%':>6} {'FPR%':>6}")
    for v in VERDICTS:
        x = m[v]
        print(f"{v:<10} {x['tp']:>4} {x['fp']:>4} {x['fn']:>4} {x['tn']:>4} | {pct(x['precision']):>6} {pct(x['recall']):>6} {pct(x['fpr']):>6}"
              + ("   (FPR = abstention rate)" if v == "AMBIGUOUS" else ""))
    c = critical(rows)
    print("critical: false assurance (PATCHED on vulnerable/near-miss) {}/{} | false alarm (UNPATCHED on non-vulnerable) {}/{} | "
          "alarm on unrelated code {}/{} | fuzzy-tier UNPATCHED precision {}/{}".format(
              *c["false_assurance"], *c["false_alarm"], *c["false_alarm_on_unrelated"], *c["fuzzy_unpatched_precision"]))
    cats = collections.OrderedDict()
    for r in rows:
        cats.setdefault(r["category"], collections.Counter())[outcome(r)] += 1
    print(f"{'category':<18} {'n':>4} {'ok':>4} {'abst':>5} {'wrong':>6}")
    for k, c2 in cats.items():
        print(f"{k:<18} {sum(c2.values()):>4} {c2['correct']:>4} {c2['abstain']:>5} {c2['wrong']:>6}")
    ok = sum(1 for r in rows if outcome(r) == "correct")
    print(f"{'TOTAL':<18} {len(rows):>4} {ok:>4} {sum(1 for r in rows if outcome(r) == 'abstain'):>5} "
          f"{sum(1 for r in rows if outcome(r) == 'wrong'):>6}")
    return m


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe")
    ap.add_argument("--split", choices=["dev", "test"], default="dev")
    ap.add_argument("--patches")
    ap.add_argument("--out")
    ap.add_argument("--compare")
    ap.add_argument("--show-wrong", action="store_true")
    ap.add_argument("--freeze", action="store_true")
    ap.add_argument("--engine-args", default="", help="extra patchgap args, e.g. '--k 6'")
    a = ap.parse_args()

    frozen = BENCH / "FROZEN.json"
    if a.freeze:
        frozen.write_text(json.dumps(dict(src_sha256=src_hash(), frozen_at=time.strftime("%Y-%m-%d %H:%M:%S"),
                                          labels_sha256=hashlib.sha256((BENCH / "labels.tsv").read_bytes()).hexdigest()), indent=1))
        print("frozen:", src_hash())
        return
    if a.split == "test":
        if not frozen.exists() or json.loads(frozen.read_text())["src_sha256"] != src_hash():
            sys.exit("refusing to run the held-out split: run `metrics.py --freeze` once, after the last engine change,"
                     " and do not edit src/ afterwards (otherwise the test split is no longer unseen).")
    exe = find_exe(a.exe)
    lab = labels()
    patches = [p for p in PATCHDIR if SPLIT[p] == a.split]
    if a.patches:
        patches = [p for p in a.patches.split(",") if p in PATCHDIR]
    allrows = []
    for p in patches:
        got = run(exe, p, a.engine_args.split())
        for (pp, cid), meta in lab.items():
            if pp != p:
                continue
            if cid not in got:
                sys.exit(f"missing verdict for {p}/{cid}")
            allrows.append({**meta, **got[cid]})
    print(f"engine src sha256: {src_hash()[:16]}  split={a.split}  exe={exe}")
    per = {}
    for p in patches:
        per[p] = report(p, [r for r in allrows if r["patch"] == p])
    pooled = report("POOLED " + "+".join(patches), allrows) if len(patches) > 1 else per[patches[0]]
    if a.show_wrong:
        print("\n-- wrong / abstained cases")
        for r in allrows:
            o = outcome(r)
            if o != "correct":
                print(f"{o:<8} {r['patch']:<8} {r['id']:<34} label={r['label']:<12} got={r['verdict']:<10} "
                      f"{r['tier']:<5} ctx={r['ctx']:.2f} old={r['old']:.2f} new={r['new']:.2f}")
    if a.compare:
        prev = {(r["patch"], r["id"]): r for r in json.loads(Path(a.compare).read_text())["rows"]}
        flips = collections.defaultdict(list)
        for r in allrows:
            q = prev.get((r["patch"], r["id"]))
            if q and outcome(q) != outcome(r):
                flips[f"{outcome(q)} -> {outcome(r)}"].append(f"{r['patch']}/{r['id']}")
        print("\n-- changes vs", a.compare)
        for k, v in sorted(flips.items()):
            print(f"{k}: {len(v)}")
            if a.show_wrong or len(v) <= 8:
                for i in v:
                    print("   ", i)
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(json.dumps(dict(src_sha256=src_hash(), split=a.split, rows=allrows), indent=0))
        print("\nwrote", a.out)


if __name__ == "__main__":
    main()

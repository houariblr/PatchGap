#!/usr/bin/env python3
"""Download verified Solidity sources from Sourcify (API v2) for patchgap.

Standard library only. Polite by default: one request at a time, a pause
between requests, backs off on 429/5xx, resumes where it stopped.

  python tools/fetch_sourcify.py --chain 1 --count 500 --out corpus

Layout written: <out>/<chain>/<address>/<source path>.sol
Progress is kept in <out>/<chain>/_state.json so a rerun continues.
"""
import argparse, json, os, re, sys, time, urllib.request, urllib.error

def get(url, retries=5):
    delay = 5
    for _ in range(retries):
        req = urllib.request.Request(url, headers={"User-Agent": "patchgap-research/0.1"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if e.code in (429, 500, 502, 503, 504):
                wait = int(e.headers.get("Retry-After", delay)) if e.code == 429 else delay
                print(f"  HTTP {e.code}, waiting {wait}s", file=sys.stderr)
                time.sleep(wait); delay = min(delay * 2, 120); continue
            raise
        except (urllib.error.URLError, TimeoutError):
            time.sleep(delay); delay = min(delay * 2, 120)
    return None

def safe_rel(path):
    # Source paths come from the network: never let them leave the target dir.
    parts = [re.sub(r"[^A-Za-z0-9._@+-]", "_", p) for p in path.replace("\\", "/").split("/")]
    parts = [p for p in parts if p not in ("", ".", "..")]
    return os.path.join(*parts) if parts else None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chain", default="1", help="chain id (1 = Ethereum mainnet)")
    ap.add_argument("--count", type=int, default=500, help="contracts to download this run")
    ap.add_argument("--out", default="corpus")
    ap.add_argument("--sort", choices=["asc", "desc"], default="asc",
                    help="asc = oldest first (vulnerable OZ versions are from 2021-2023)")
    ap.add_argument("--pause", type=float, default=1.0, help="seconds between requests")
    ap.add_argument("--base-url", default="https://sourcify.dev/server")
    a = ap.parse_args()
    if not a.chain.isdigit():
        sys.exit("--chain must be a number")

    root = os.path.join(a.out, a.chain)
    os.makedirs(root, exist_ok=True)
    sp = os.path.join(root, "_state.json")
    state = json.load(open(sp)) if os.path.exists(sp) else {}
    after = state.get(a.sort)
    done = 0
    while done < a.count:
        q = f"{a.base_url}/v2/contracts/{a.chain}?limit=100&sort={a.sort}"
        if after: q += f"&afterMatchId={after}"
        page = get(q); time.sleep(a.pause)
        items = (page or {}).get("results") or []
        if not items:
            print("no more contracts"); break
        for it in items:
            after = it.get("matchId", after)
            addr = it.get("address", "")
            if not re.fullmatch(r"0x[0-9a-fA-F]{40}", addr):
                continue
            d = os.path.join(root, addr.lower())
            if os.path.isdir(d):
                continue
            c = get(f"{a.base_url}/v2/contract/{a.chain}/{addr}?fields=sources"); time.sleep(a.pause)
            n = 0
            for path, v in ((c or {}).get("sources") or {}).items():
                rel = safe_rel(path)
                if not rel or not rel.endswith(".sol") or not isinstance(v, dict):
                    continue
                dest = os.path.join(d, rel)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with open(dest, "w", encoding="utf-8") as f:
                    f.write(v.get("content", ""))
                n += 1
            os.makedirs(d, exist_ok=True)  # mark as done even if no .sol files
            done += 1
            if done % 25 == 0:
                print(f"{done}/{a.count} contracts")
            if done >= a.count: break
        state[a.sort] = after
        json.dump(state, open(sp, "w"))
    state[a.sort] = after
    json.dump(state, open(sp, "w"))
    print(f"done: {done} new contracts in {root}")

if __name__ == "__main__":
    main()

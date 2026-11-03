#!/usr/bin/env python3
"""Download the real third-party files the benchmark needs (public GitHub raw URLs).

  python bench/fetch_data.py

Writes bench/data/** and bench/data/MANIFEST.tsv (url, sha256). Needs network;
the files are committed in bench/data except solmate_ERC20.sol (AGPL), which only this script fetches.
"""
import hashlib, os, sys, urllib.request

OZ = "https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts"
TAGS = ("v4.0.0 v4.1.0 v4.2.0 v4.3.0 v4.3.1 v4.3.2 v4.3.3 v4.4.0 v4.4.1 v4.4.2 v4.5.0 v4.6.0 "
        "v4.7.0 v4.7.1 v4.7.2 v4.7.3 v4.8.0 v4.8.1 v4.8.2 v4.8.3 v4.9.0 v4.9.1 v4.9.2 v4.9.3 "
        "v4.9.4 v4.9.5 v4.9.6 v5.0.0 v5.0.1 v5.0.2 v5.1.0 v5.2.0 v5.3.0 v5.4.0 v5.5.0 v5.6.0 "
        "v5.6.1 v5.7.0").split()

jobs = []  # (url, relative output path)
for t in TAGS:  # held-out patch: ERC2771Context, same tag grid as the ECDSA/Merkle sets
    jobs.append((f"{OZ}/{t}/contracts/metatx/ERC2771Context.sol", f"erc2771/ERC2771Context_{t}.sol"))
for t in TAGS:  # 4th patch (unseen test split): UUPSUpgradeable onlyProxy, fixed in 4.3.2 (file exists from 4.1.0)
    jobs.append((f"{OZ}/{t}/contracts/proxy/utils/UUPSUpgradeable.sol", f"uups/UUPSUpgradeable_{t}.sol"))
NEG = {  # similar-looking code that is NOT a copy of the patched OpenZeppelin code
    "solady_ECDSA.sol": "https://raw.githubusercontent.com/Vectorized/solady/main/src/utils/ECDSA.sol",
    "solady_SignatureCheckerLib.sol": "https://raw.githubusercontent.com/Vectorized/solady/main/src/utils/SignatureCheckerLib.sol",
    "solady_MerkleProofLib.sol": "https://raw.githubusercontent.com/Vectorized/solady/main/src/utils/MerkleProofLib.sol",
    "solmate_MerkleProofLib.sol": "https://raw.githubusercontent.com/transmissions11/solmate/main/src/utils/MerkleProofLib.sol",
    "solmate_ERC20.sol": "https://raw.githubusercontent.com/transmissions11/solmate/main/src/tokens/ERC20.sol",
    "permit2_SignatureVerification.sol": "https://raw.githubusercontent.com/Uniswap/permit2/main/src/libraries/SignatureVerification.sol",
    "oz496_SignatureChecker.sol": f"{OZ}/v4.9.6/contracts/utils/cryptography/SignatureChecker.sol",
    "oz496_EIP712.sol": f"{OZ}/v4.9.6/contracts/utils/cryptography/EIP712.sol",
    "oz496_Context.sol": f"{OZ}/v4.9.6/contracts/utils/Context.sol",
    "oz496_MinimalForwarder.sol": f"{OZ}/v4.9.6/contracts/metatx/MinimalForwarder.sol",
    "oz496_Multicall.sol": f"{OZ}/v4.9.6/contracts/utils/Multicall.sol",
    "oz496_ERC20.sol": f"{OZ}/v4.9.6/contracts/token/ERC20/ERC20.sol",
    "oz510_ERC2771Forwarder.sol": f"{OZ}/v5.1.0/contracts/metatx/ERC2771Forwarder.sol",
    "oz496_Strings.sol": f"{OZ}/v4.9.6/contracts/utils/Strings.sol",
}
for name, url in NEG.items():
    jobs.append((url, f"neg/{name}"))

here = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
rows, bad = [], 0
for url, rel in jobs:
    out = os.path.join(here, *rel.split("/"))
    os.makedirs(os.path.dirname(out), exist_ok=True)
    try:
        data = urllib.request.urlopen(url, timeout=60).read()
    except Exception as e:  # noqa
        if "/uups/" in out.replace("\\", "/") and getattr(e, "code", 0) == 404:
            continue  # the file does not exist in this tag
        print("FAIL", url, e, file=sys.stderr); bad += 1; continue
    open(out, "wb").write(data)
    rows.append(f"{rel}\t{hashlib.sha256(data).hexdigest()}\t{url}")
open(os.path.join(here, "MANIFEST.tsv"), "w", newline="\n").write("\n".join(rows) + "\n")
print(len(rows), "files,", bad, "failed")
sys.exit(1 if bad else 0)

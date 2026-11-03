import re, subprocess, sys
exe, old, new, targets, k = sys.argv[1:6]
out = subprocess.run([exe, '--old', old, '--new', new, '--k', k, '--all', targets],
                     capture_output=True, text=True).stdout
def ver(tag):
    return tuple(int(x) for x in re.findall(r'\d+', tag)[:3])
rows = []
for line in out.splitlines():
    m = re.match(r'(\S+)\s+(exact|fuzzy)\s+ctx=([\d.]+) old=([\d.]+) new=([\d.]+)\s+(\S+)', line)
    if not m: continue
    tag = re.search(r'ECDSA_(v[\d.]+)\.sol', m.group(6)).group(1)
    v = ver(tag)
    if v >= (4, 7, 3): exp = 'PATCHED'
    elif v >= (4, 1, 0): exp = 'UNPATCHED'
    else: exp = 'not-affected'   # before EIP-2098 support existed
    rows.append((v, tag, m.group(1), exp, m.group(2)))
rows.sort()
bad = 0
for v, tag, got, exp, tier in rows:
    ok = got == exp or (exp == 'not-affected' and got in ('NO_MATCH', 'AMBIGUOUS', 'PATCHED'))
    # "not-affected" files have no 64-byte branch; any non-UNPATCHED verdict is acceptable
    if exp == 'not-affected': ok = got != 'UNPATCHED'
    if not ok: bad += 1
    print(f"{'OK ' if ok else 'BAD'} {tag:<9} expected={exp:<12} got={got:<10} tier={tier}")
ex=sum(1 for r in rows if r[4]=='exact')
print(f"\n{len(rows)} files, {bad} wrong, {ex} settled by the exact tier")

import re,subprocess,sys
exe,d=sys.argv[1],sys.argv[2]; old,new=sys.argv[3],sys.argv[4]
key=lambda v:tuple(int(x) for x in v.split('.'))
out=subprocess.run([exe,'--old',old,'--new',new,'--all',d+'/targets'],capture_output=True,text=True).stdout
ok=bad=0
for l in out.splitlines():
    verdict,tier=l.split()[:2]; v=re.search(r'_v([\d.]+)\.sol',l).group(1); k=key(v)
    truth='patched' if k>=(4,9,2) else 'UNPATCHED' if k>=(4,7,0) else None
    good = verdict==truth if truth else verdict in('no-match','patched')
    ok+=good; bad+=not good
    if not good: print('WRONG',v,verdict,tier,'truth',truth)
print(ok,'correct,',bad,'wrong')

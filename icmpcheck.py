#!/usr/bin/env python3
import sys,os,subprocess,threading,datetime
if os.geteuid()!=0: os.execvp("sudo",["sudo",sys.executable]+sys.argv)
from rich.console import Console
from rich.table import Table
con=Console()
args=sys.argv[1:]; v="--vulnerable" in args; f=""
for a in reversed(args):
    if a!="--vulnerable": f=a; break
key=Table(title="KEY",show_lines=True)
key.add_column("Status"); key.add_column("Meaning")
key.add_row("🟢","VULNERABLE (answers ICMP timestamp)")
key.add_row("🔴","NOT VULNERABLE (no reply/filtered)")
key.add_row("⚪","ERROR (hping3 missing / request failed)")
con.print(key)
res=[]
def s(i):
    try:
        o=subprocess.run(["hping3","--icmp","--icmptype","13","-c","1",i],
            stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=4).stdout.decode(errors="ignore")
        if "ICMP timestamp: Originate" in o:
            out=[f"🟢 {i}"]
            for l in o.splitlines():
                if "timestamp:" in l.lower():
                    out.append("   ICMP: "+l.split(":",1)[1].strip())
                    t="   UTC:  "
                    for p in l.split():
                        if "=" in p:
                            try:
                                k,val=p.split("="); ms=int(val)%86400000
                                d=datetime.datetime.now(datetime.timezone.utc).replace(hour=0,minute=0,second=0,microsecond=0)+datetime.timedelta(milliseconds=ms)
                                t+=k+"="+d.strftime("%H:%M:%S")+" "
                            except: pass
                    out.append(t.rstrip()); break
            res.append("\n".join(out))
        elif not v: res.append(f"🔴 {i}")
    except Exception as e:
        res.append(f"⚪ {i} {e}")
if not f: sys.exit("Usage: icmpcheck.py [--vulnerable] <hosts-file>")
ts=[]
for l in open(f):
    i=l.strip()
    if i and not i.startswith('#'):
        th=threading.Thread(target=s,args=(i,)); th.start(); ts.append(th)
for th in ts: th.join()
for r in res: print(r)

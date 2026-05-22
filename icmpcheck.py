#!/usr/bin/env python3
import sys,subprocess,threading,datetime
args = sys.argv[1:]
v = "--vulnerable" in args
t = []

for a in reversed(args):
    if a != "--vulnerable":
        f = a
        break
else:
    f = ""

def s(i):
    try:
        r = subprocess.run(["sudo","hping3","--icmp","--icmptype","13","-c","2",i],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=4)
        o = r.stdout.decode(errors="ignore")
        if "ICMP timestamp: Originate" in o:
            print(f"{i:<20} ✗")
            for l in o.splitlines():
                if "timestamp:" in l.lower():
                    raw = l.split(":",1)[1].strip()
                    print("   ICMP: " + raw)
                    times = "   UTC:  "
                    for p in l.split():
                        if "=" in p:
                            try:
                                k,val = p.split("=")
                                ms = int(val) % 86400000
                                d = datetime.datetime.now(datetime.timezone.utc).replace(hour=0,minute=0,second=0,microsecond=0) + datetime.timedelta(milliseconds=ms)
                                times += k + "=" + d.strftime("%H:%M:%S") + " "
                            except: pass
                    print(times.rstrip())
                    break
        elif not v:
            print(f"{i:<20} ✓")
    except:
        if not v:
            print(f"{i:<20} ✓")

if not f:
    print("Usage: icmpcheck.py [--vulnerable] <hosts-file>")
    sys.exit(1)

with open(f) as x:
    for l in x:
        i = l.strip()
        if i and not i.startswith('#'):
            t.append(i)

for i in t:
    threading.Thread(target=s, args=(i,), daemon=True).start()

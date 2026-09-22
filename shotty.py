#!/usr/bin/env python3
# shott.py — screenshot a list of URLs, optional SOCKS4/5 proxy
# usage: shot.py urls.txt [-p socks5://127.0.0.1:9050] [-o shots] [-t 4] [-w 1280 -h 800] [--timeout 15000]
import sys, os, queue, threading, argparse, shutil
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright

def browser_exe():
    for c in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"):
        p = shutil.which(c)
        if p: return p
    return None

def shot(q, proxy, o, w, h, t, lock, exe):
    with sync_playwright() as p:
        kw = {"proxy": {"server": proxy}} if proxy else {}
        if exe: kw["executable_path"] = exe
        b = p.chromium.launch(args=["--no-sandbox"], **kw)
        while True:
            try: u = q.get_nowait()
            except queue.Empty: break
            n = urlparse(u).netloc.replace(":", "_") or "index"
            fn = os.path.join(o, n + ".png")
            try:
                pg = b.new_page(viewport={"width": w, "height": h})
                r = pg.goto(u, timeout=t, wait_until="domcontentloaded")
                pg.wait_for_timeout(1500)
                pg.screenshot(path=fn, full_page=False)
                with lock: print(f"[{r.status if r else '??'}] {u} -> {fn}")
                pg.close()
            except Exception as e:
                with lock: print(f"[ERR] {u} {str(e).splitlines()[0][:80]}")
            q.task_done()

def main():
    a = argparse.ArgumentParser(
        description="Screenshot a list of URLs.",
        epilog="""examples:
  shotty.py urls.txt                          plain, saves to shots/
  shotty.py urls.txt -p socks5://127.0.0.1:9050
  shotty.py urls.txt -p 127.0.0.1:1080        defaults to socks5
  shotty.py urls.txt -p socks4://127.0.0.1:40000 -o out -t 8
  shotty.py -p socks5://127.0.0.1:9050        reads ./urls.txt by default
""",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument("list", nargs="?", default="urls.txt", metavar="urls.txt",
                   help="file with one URL per line (default: urls.txt)")
    a.add_argument("-p", "--proxy", metavar="PROXY",
                   help="proxy: socks5://ip:port | socks4://ip:port | http://ip:port (bare ip:port = socks5)")
    a.add_argument("-o", default="shots", metavar="DIR", help="output directory (default: shots)")
    a.add_argument("-t", type=int, default=4, metavar="N", help="threads (default: 4)")
    a.add_argument("-w", type=int, default=1280, metavar="W", help="viewport width (default: 1280)")
    a.add_argument("--height", type=int, default=800, metavar="H", help="viewport height (default: 800)")
    a.add_argument("--timeout", type=int, default=15000, metavar="MS", help="page timeout ms (default: 15000)")
    a.add_argument("--chrome", metavar="PATH", help="explicit chrome/chromium binary (default: auto-detect system browser, else playwright's)")
    x = a.parse_args()
    if not os.path.isfile(x.list):
        a.print_help(sys.stderr)
        a.exit(1, f"\n{a.prog}: error: {x.list}: file not found\n")
    exe = x.chrome or browser_exe()
    if x.proxy and "://" not in x.proxy: x.proxy = "socks5://" + x.proxy
    os.makedirs(x.o, exist_ok=True)
    q = queue.Queue()
    for l in open(x.list):
        u = l.strip()
        if not u: continue
        if "://" not in u: u = "http://" + u
        q.put(u)
    lock = threading.Lock()
    ts = [threading.Thread(target=shot, args=(q, x.proxy, x.o, x.w, x.height, x.timeout, lock, exe)) for _ in range(x.t)]
    [t.start() for t in ts]; [t.join() for t in ts]

if __name__ == "__main__":
    main()

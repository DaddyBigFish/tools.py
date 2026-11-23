#!/usr/bin/env python3
import asyncio, argparse, time, shutil, sys, socket, struct

if sys.platform == 'win32':
    import ctypes; ctypes.cdll.msvcrt._setmaxstdio(8192)
else:
    import resource
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (min(65535, hard) if hard != resource.RLIM_INFINITY else 65535, hard))
    except (ValueError, OSError):
        pass

def fmt(s):
    h, s = divmod(max(0, int(s)), 3600)
    m, s = divmod(s, 60)
    return f"{h}h{m:02d}m{s:02d}s" if h else f"{m}m{s:02d}s"

async def socks_connect(proxy, host, port, rdns):
    """SOCKS5 CONNECT (no-auth). rdns=True -> remote DNS (ATYP=domain, like curl --socks5h)."""
    ph, pp = proxy
    r, w = await asyncio.open_connection(ph, pp)
    w.write(b"\x05\x01\x00"); await w.drain()                      # greeting: v5, 1 method, no-auth
    if await r.readexactly(2) != b"\x05\x00":
        w.close(); raise OSError("SOCKS5: no-auth method rejected")
    if rdns:                                                      # remote resolves the name
        hb = host.encode()
        addr = b"\x03" + bytes([len(hb)]) + hb
    else:                                                         # local resolve, send IPv4
        addr = b"\x01" + socket.inet_aton(socket.gethostbyname(host))
    w.write(b"\x05\x01\x00" + addr + struct.pack(">H", port)); await w.drain()
    head = await r.readexactly(4)
    if head[1] != 0x00:
        w.close(); raise OSError(f"SOCKS5 connect refused (code {head[1]})")
    atyp = head[3]                                                # drain bound address
    if atyp == 1:   await r.readexactly(4)
    elif atyp == 3: await r.readexactly((await r.readexactly(1))[0])
    else:           await r.readexactly(16)
    await r.readexactly(2)                                        # bound port
    return w

async def probe(host, port, timeout, proxy=None, rdns=False):
    try:
        if proxy:
            w = await asyncio.wait_for(socks_connect(proxy, host, port, rdns), timeout)
        else:
            _, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        w.close()
        return port
    except Exception:
        return None

async def run(args):
    s, e = map(int, args.range.split('-')) if '-' in args.range else (int(args.range),) * 2
    try:
        hosts = [h for h in open(args.target).read().splitlines() if h.strip()]
    except Exception:
        hosts = [args.target]

    proxy, rdns = None, False
    raw = args.socks5 or args.socks5h
    if raw:
        rdns = bool(args.socks5h)
        ph, _, ps = raw.partition(":")
        proxy = (ph, int(ps) if ps else 1080)

    total = (e - s + 1) * len(hosts)
    done, found_total, start = 0, 0, time.time()
    tty = sys.stdout.isatty()
    BAR_W = 25

    def status(host, idx):
        # fresh width every draw -> resize-safe; \x1b[2K erases the line cleanly
        cols = shutil.get_terminal_size((80, 20)).columns
        elapsed = time.time() - start
        pct = int(done * 100 / total) if total else 100
        if done == 0:
            eta = "--"
        elif done >= total:
            eta = fmt(0)
        else:
            eta = fmt((total - done) / (done / elapsed))
        fill = pct * BAR_W // 100
        bar = "█" * fill + "░" * (BAR_W - fill)
        line = f"{host:<24} [{bar}] {pct:3d}%  {found_total} open  ETA {eta}  ({idx}/{len(hosts)})"
        if tty:
            sys.stdout.write("\x1b[2K\r" + line[: max(cols - 1, 10)])
        else:
            sys.stdout.write(line + "\n")
        sys.stdout.flush()

    def found(host, port):
        # ports print the instant they're identified — the status line
        # re-renders underneath on the next tick
        if tty:
            sys.stdout.write(f"\x1b[2K\r{host}:{port} open\n")
        else:
            sys.stdout.write(f"{host}:{port} open\n")
        sys.stdout.flush()

    tick = 0.1 if tty else 5.0

    for idx, host in enumerate(hosts, 1):
        ports = iter(range(s, e + 1))
        last = 0.0

        async def worker():
            nonlocal done, found_total, last
            for port in ports:
                if (result := await probe(host, port, args.timeout, proxy, rdns)) is not None:
                    found_total += 1
                    found(host, result)
                done += 1
                if (now := time.time()) - last >= tick and done < total:
                    last = now
                    status(host, idx)

        status(host, idx)
        await asyncio.gather(*[asyncio.create_task(worker()) for _ in range(min(args.concurrency, e - s + 1))])
        if tty:
            sys.stdout.write("\x1b[2K\r")
            sys.stdout.flush()
        else:
            status(host, idx)

    sys.stdout.write(f"done: {found_total} open across {len(hosts)} host(s) in {fmt(time.time() - start)}\n")

def main():
    p = argparse.ArgumentParser()
    p.add_argument("target")
    p.add_argument("range", nargs="?", default="0-65535")
    p.add_argument("--timeout", type=float, default=15.0)
    p.add_argument("--concurrency", type=int, default=65535)
    p.add_argument("--socks5", metavar="HOST[:PORT]", help="SOCKS5 proxy, local DNS (default port 1080)")
    p.add_argument("--socks5h", metavar="HOST[:PORT]", help="SOCKS5 proxy, remote DNS (like curl --socks5h)")
    args = p.parse_args()
    if args.socks5 and args.socks5h:
        p.error("use --socks5 or --socks5h, not both")
    if (args.socks5 or args.socks5h):
        if args.timeout == 15.0: args.timeout = 5.0        # saner tunnel defaults
        if args.concurrency == 65535: args.concurrency = 100
    asyncio.run(run(args))

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import asyncio, argparse, time, shutil, sys

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

async def probe(host, port, timeout):
    try:
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

    total = (e - s + 1) * len(hosts)
    done, start = 0, time.time()
    W = shutil.get_terminal_size().columns

    def draw(host, pct=None, found=0):
        elapsed = time.time() - start
        pct = pct if pct is not None else int(done * 100 / total)
        eta = "--" if pct < 1 else fmt(0) if pct == 100 else fmt((total - done) / (done / elapsed))
        bar = "█" * (pct * 30 // 100) + "░" * (30 - pct * 30 // 100)
        print(f"\r{f'{host:<20} [{bar}] {pct:3d}%  ({found} open)  ETA: {eta}':<{W}}", end="", flush=True)

    for host in hosts:
        ports = iter(range(s, e + 1))
        last, open_ports = 0.0, []

        async def worker():
            nonlocal done, last
            for port in ports:
                if (result := await probe(host, port, args.timeout)) is not None:
                    open_ports.append(result)
                done += 1
                if (now := time.time()) - last >= 0.1 and done < total:
                    last = now; draw(host, found=len(open_ports))

        draw(host, 0, found=0)
        await asyncio.gather(*[asyncio.create_task(worker()) for _ in range(min(args.concurrency, e - s + 1))])
        print(f"\r{' ' * W}", end="")
        for port in sorted(open_ports):
            print(f"\r{host}:{port} open")

def main():
    p = argparse.ArgumentParser()
    p.add_argument("target")
    p.add_argument("range", nargs="?", default="0-65535")
    p.add_argument("--timeout", type=float, default=15.0)
    p.add_argument("--concurrency", type=int, default=65535)
    p.add_argument("--proxy", action="store_true")
    args = p.parse_args()
    if args.proxy: args.timeout, args.concurrency = 5.0, 50
    asyncio.run(run(args))

if __name__ == "__main__":
    main()

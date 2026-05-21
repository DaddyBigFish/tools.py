#!/usr/bin/env python3
import sys
import socket
import argparse
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import shutil

def format_time(seconds):
    if seconds < 0: seconds = 0
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = int(seconds % 60)
    if h > 0:
        return f"{h}h{m:02d}m{s:02d}s"
    return f"{m}m{s:02d}s"

def scan_port(host, port, timeout=1.5):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            return f"{host}:{port} open"
    except:
        return None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="IP or file with IPs")
    parser.add_argument("range", nargs="?", default="0-65000")
    parser.add_argument("--timeout", type=float, default=1.5)
    parser.add_argument("--open", action="store_true")
    args = parser.parse_args()

    if '-' in args.range:
        s, e = map(int, args.range.split('-'))
    else:
        s = e = int(args.range)

    try:
        with open(args.target) as f:
            hosts = [line.strip() for line in f if line.strip()]
    except:
        hosts = [args.target]

    total = (e - s + 1) * len(hosts)
    start = time.time()
    done = 0
    term_width = shutil.get_terminal_size().columns
    clear_len = term_width - 10   # safe clear length

    for host in hosts:
        with ThreadPoolExecutor(max_workers=50000) as executor:
            futures = [executor.submit(scan_port, host, p, args.timeout) for p in range(s, e+1)]

            for future in as_completed(futures):
                result = future.result()
                if result:
                    print(f"\r{' ' * clear_len}\r{result}")

                done += 1
                if done % 20 == 0 or done == total:
                    elapsed = time.time() - start
                    percent = int(done * 100 / total)
                    bar_width = 30
                    filled = int(percent * bar_width / 100)
                    bar = "█" * filled + "░" * (bar_width - filled)
                    eta = (total - done) / (done / elapsed) if elapsed > 0 and done > 0 else 0

                    print(f"\r{host:<20} [{bar}] {percent:3d}%    ETA: {format_time(eta)}", end="", flush=True)

    print("\n" + "="*90)
    print("SCAN COMPLETE")
    print("="*90)

if __name__ == "__main__":
    main()

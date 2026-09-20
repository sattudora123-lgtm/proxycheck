#!/usr/bin/env python3
"""proxycheck - async proxy checker: alive/dead, latency, anonymity level.

Usage:
    pip install httpx sniffio    # add httpx[socks] for socks4/socks5 proxies
    python proxycheck.py proxies.txt --out results.json

proxies.txt: one proxy per line. Accepted formats:
    1.2.3.4:8080
    http://user:pass@1.2.3.4:8080
    socks5://1.2.3.4:1080
"""
import argparse
import asyncio
import json
import os
import sys
import time

import httpx

TEST_URL = "https://httpbin.org/get"  # echoes origin IP + request headers
LEAK_HEADERS = ("via", "x-forwarded-for", "forwarded", "x-real-ip", "proxy-connection")

# Build the SSL context ONCE. Creating one per client reloads the CA bundle
# every time, which blocks the event loop and makes big runs crawl.
SSL_CTX = httpx.create_ssl_context()


def normalize(line: str):
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    return line if "://" in line else f"http://{line}"


async def get_real_ip(url: str, timeout: float) -> str:
    async with httpx.AsyncClient(timeout=timeout, verify=SSL_CTX) as client:
        r = await client.get(url)
        r.raise_for_status()
        return r.json().get("origin", "").split(",")[0].strip()


def classify(data: dict, real_ip: str) -> str:
    origin = data.get("origin", "")
    headers = {k.lower(): str(v) for k, v in data.get("headers", {}).items()}
    if real_ip and (real_ip in origin or any(real_ip in v for v in headers.values())):
        return "transparent"  # your real IP is visible
    if any(h in headers for h in LEAK_HEADERS):
        return "anonymous"  # IP hidden, but proxy use is detectable
    return "elite"  # no obvious proxy signals


async def check(proxy: str, url: str, real_ip: str, timeout: float, sem: asyncio.Semaphore) -> dict:
    result = {"proxy": proxy, "alive": False}

    async def fetch():
        async with httpx.AsyncClient(proxy=proxy, timeout=timeout, verify=SSL_CTX) as client:
            r = await client.get(url)
            r.raise_for_status()
            return r.json()

    async with sem:
        start = time.perf_counter()
        task = asyncio.ensure_future(fetch())
        # swallow errors from tasks that finish after we gave up on them
        task.add_done_callback(lambda t: t.cancelled() or t.exception())
        done, _ = await asyncio.wait({task}, timeout=timeout)
        if not done:
            task.cancel()  # don't await it: stuck-socket cleanup can hang for ages
            result["error"] = "TimeoutError"
            return result
        try:
            data = task.result()
        except Exception as e:  # dead, bad auth, bad JSON, etc.
            result["error"] = type(e).__name__
            return result
    result.update(
        alive=True,
        latency_ms=round((time.perf_counter() - start) * 1000),
        anonymity=classify(data, real_ip),
        exit_ip=data.get("origin", "").split(",")[0].strip(),
    )
    return result


async def main() -> int:
    ap = argparse.ArgumentParser(description="Async proxy checker")
    ap.add_argument("file", help="text file with one proxy per line")
    ap.add_argument("--url", default=TEST_URL, help="echo endpoint (must return httpbin-style JSON)")
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--concurrency", type=int, default=50)
    ap.add_argument("--out", default="results.json")
    ap.add_argument("--alive-only", action="store_true", help="only keep working proxies in output")
    args = ap.parse_args()

    with open(args.file) as f:
        proxies = [p for p in map(normalize, f) if p]
    if not proxies:
        print("no proxies found in file", file=sys.stderr)
        return 1

    try:
        real_ip = await get_real_ip(args.url, args.timeout)
    except Exception as e:
        print(f"couldn't detect your real IP ({type(e).__name__}); check your connection", file=sys.stderr)
        return 1

    sem = asyncio.Semaphore(args.concurrency)
    print(f"checking {len(proxies)} proxies (concurrency={args.concurrency})...")

    tasks = [check(p, args.url, real_ip, args.timeout, sem) for p in proxies]
    results, alive_count = [], 0
    try:
        for coro in asyncio.as_completed(tasks):
            r = await coro
            results.append(r)
            alive_count += r["alive"]
            print(f"\rchecked {len(results)}/{len(proxies)} | alive: {alive_count}", end="", flush=True)
    except (asyncio.CancelledError, KeyboardInterrupt):
        print("\nstopped by user")
        os._exit(130)  # skip asyncio's slow shutdown of stuck sockets
    print()

    alive = sorted((r for r in results if r["alive"]), key=lambda r: r["latency_ms"])
    dead = [r for r in results if not r["alive"]]

    for r in alive[:20]:
        print(f"{r['latency_ms']:>6} ms  {r['anonymity']:<11} {r['proxy']}")
    print(f"\nalive: {len(alive)}  dead: {len(dead)}")

    with open(args.out, "w") as f:
        json.dump(alive if args.alive_only else alive + dead, f, indent=2)
    print(f"saved -> {args.out}")
    sys.stdout.flush()
    os._exit(0)  # exit now; don't wait on asyncio to tear down leftover sockets


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
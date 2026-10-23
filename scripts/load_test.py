#!/usr/bin/env python3
"""Simple load test for the WAF detection API /check endpoint."""

import argparse
import asyncio
import json
import time
import uuid

import httpx


async def worker(client: httpx.AsyncClient, url: str, key: str, n: int, unique: bool):
    ok = blocked = err = 0
    for _ in range(n):
        path = f"/products?id=1&n={uuid.uuid4().hex}" if unique else "/products?id=1"
        try:
            r = await client.post(
                url,
                json={"method": "GET", "path": path, "headers": {"User-Agent": "loadtest"}, "body": ""},
                headers={"X-API-Key": key},
            )
            if r.status_code == 204:
                ok += 1
            elif r.status_code == 403:
                blocked += 1
            else:
                err += 1
        except Exception:
            err += 1
    return ok, blocked, err


async def main():
    p = argparse.ArgumentParser()
    p.add_argument("--url", default="http://127.0.0.1:8080/check")
    p.add_argument("--key", default="waf-key-dev-001")
    p.add_argument("--concurrency", type=int, default=20)
    p.add_argument("--requests", type=int, default=200)
    p.add_argument("--unique", action="store_true", help="disable cache hits (worst case)")
    args = p.parse_args()

    limits = httpx.Limits(max_connections=args.concurrency)
    async with httpx.AsyncClient(timeout=30, limits=limits) as client:
        start = time.time()
        per = args.requests // args.concurrency
        tasks = [
            asyncio.create_task(worker(client, args.url, args.key, per, args.unique))
            for _ in range(args.concurrency)
        ]
        results = await asyncio.gather(*tasks)
        elapsed = time.time() - start
    ok = blocked = err = 0
    for o, b, e in results:
        ok += o
        blocked += b
        err += e
    print(json.dumps({"ok": ok, "blocked": blocked, "errors": err, "elapsed_s": round(elapsed, 3), "rps": round((ok+blocked+err)/elapsed, 1)}))


if __name__ == "__main__":
    asyncio.run(main())

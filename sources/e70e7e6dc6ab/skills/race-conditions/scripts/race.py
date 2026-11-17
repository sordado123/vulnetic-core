#!/usr/bin/env python3
"""race.py — fire N identical HTTP requests as close to simultaneously as
possible, single-packet-attack style, to test a suspected race condition.

Uses one shared HTTP/2 connection (httpx + h2) when the server negotiates
h2, so all N requests go out multiplexed over one TCP connection instead of
opening N separate connections — this is what actually closes the timing
window; firing N plain sequential/threaded requests over separate
connections mostly just measures network jitter, not the server's race.
Falls back to httpx's default connection pool (HTTP/1.1, best-effort
concurrency) when the server does not support h2 — still useful, just a
looser race window.

Usage:
  python3 race.py --url https://target/api/redeem --method POST \\
      --header "Authorization: Bearer xyz" --header "Content-Type: application/json" \\
      --body '{"code":"WELCOME10"}' --count 30

Prints one line per response: index, status code, elapsed ms, and the first
200 chars of the body — eyeball how many came back as "success" rather than
relying on status code alone (many apps 200 both the winner and the losers).
"""
import argparse
import asyncio
import sys
import time

try:
    import httpx
except ImportError:
    print("this script needs httpx (and h2 for real HTTP/2 multiplexing): pip install httpx h2", file=sys.stderr)
    sys.exit(2)


def parse_headers(pairs: list[str]) -> dict[str, str]:
    headers = {}
    for p in pairs:
        if ":" not in p:
            print(f"ignoring malformed --header {p!r} (expected 'Name: value')", file=sys.stderr)
            continue
        k, v = p.split(":", 1)
        headers[k.strip()] = v.strip()
    return headers


async def fire_one(client: "httpx.AsyncClient", idx: int, method: str, url: str,
                    headers: dict[str, str], body: str | None, barrier: asyncio.Barrier):
    # Build the request ahead of the barrier so no per-request setup cost
    # happens after everyone is released — only the actual send is timed.
    req = client.build_request(method, url, headers=headers, content=body)
    await barrier.wait()
    t0 = time.monotonic()
    try:
        resp = await client.send(req)
        elapsed_ms = (time.monotonic() - t0) * 1000
        snippet = resp.text[:200].replace("\n", " ")
        print(f"[{idx:02d}] status={resp.status_code} elapsed={elapsed_ms:.1f}ms body={snippet!r}")
        return resp.status_code
    except Exception as e:  # noqa: BLE001 — report and keep going, one bad request should not sink the batch
        print(f"[{idx:02d}] ERROR {e}")
        return None


async def run(args: argparse.Namespace) -> None:
    headers = parse_headers(args.header or [])
    limits = httpx.Limits(max_connections=args.count, max_keepalive_connections=args.count)
    async with httpx.AsyncClient(http2=True, limits=limits, timeout=args.timeout) as client:
        barrier = asyncio.Barrier(args.count)
        tasks = [
            fire_one(client, i, args.method, args.url, headers, args.body, barrier)
            for i in range(args.count)
        ]
        results = await asyncio.gather(*tasks)
    successes = sum(1 for r in results if r is not None and 200 <= r < 300)
    print(f"\n{successes}/{args.count} requests returned a 2xx. Read the bodies above, not just "
          f"this count, to tell a real duplicate success apart from N identical-looking 200s "
          f"that are actually N rejections.")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", required=True)
    ap.add_argument("--method", default="POST")
    ap.add_argument("--header", action="append", help="repeatable: 'Name: value'")
    ap.add_argument("--body", default=None)
    ap.add_argument("--count", type=int, default=30)
    ap.add_argument("--timeout", type=float, default=15.0)
    args = ap.parse_args()
    if args.count < 2:
        print("--count must be at least 2 to race anything", file=sys.stderr)
        return 2
    asyncio.run(run(args))
    return 0


if __name__ == "__main__":
    sys.exit(main())

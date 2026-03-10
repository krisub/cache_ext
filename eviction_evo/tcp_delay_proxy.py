#!/usr/bin/env python3
"""tcp_delay_proxy.py — Userspace TCP proxy for simulating network conditions.

Sits between My-YCSB benchmark clients and net_leveldb_server, adding
configurable delay and bandwidth limits.

The proxy creates real effects observable by the BPF kprobe on port 9100:
- Request delay → larger gaps between tcp_recvmsg calls (last_packet_ts)
- Bandwidth limits → slower data flow, backpressure
- Both affect net_recv_count growth rate, net_bytes_received, etc.

Usage:
    python3 tcp_delay_proxy.py --listen-port 9101 --target-port 9100 \
        --delay-ms 25 --bandwidth-kbps 10000
"""

import argparse
import asyncio
import sys
import time


class TokenBucket:
    """Token bucket rate limiter for bandwidth control."""

    def __init__(self, rate_bytes_per_sec):
        self.rate = rate_bytes_per_sec
        self.tokens = float(rate_bytes_per_sec)
        self.last_time = time.monotonic()

    async def consume(self, nbytes):
        if self.rate <= 0:
            return
        while True:
            now = time.monotonic()
            elapsed = now - self.last_time
            self.tokens = min(self.rate, self.tokens + self.rate * elapsed)
            self.last_time = now
            if self.tokens >= nbytes:
                self.tokens -= nbytes
                return
            wait_time = (nbytes - self.tokens) / self.rate
            await asyncio.sleep(wait_time)


async def pipe(reader, writer, delay_sec, bucket):
    """Forward data from reader to writer with optional delay and rate limit."""
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            if delay_sec > 0:
                await asyncio.sleep(delay_sec)
            if bucket:
                await bucket.consume(len(data))
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def handle_connection(client_reader, client_writer,
                            target_host, target_port,
                            delay_sec, bw_bytes_per_sec):
    """Handle a single proxied connection."""
    try:
        srv_reader, srv_writer = await asyncio.open_connection(
            target_host, target_port)
    except Exception as e:
        print(f"[proxy] connect to {target_host}:{target_port} failed: {e}",
              file=sys.stderr)
        client_writer.close()
        return

    up_bucket = TokenBucket(bw_bytes_per_sec) if bw_bytes_per_sec > 0 else None
    down_bucket = TokenBucket(bw_bytes_per_sec) if bw_bytes_per_sec > 0 else None

    await asyncio.gather(
        pipe(client_reader, srv_writer, delay_sec, up_bucket),
        pipe(srv_reader, client_writer, delay_sec, down_bucket),
    )


async def run_proxy(listen_port, target_host, target_port,
                    delay_ms, bandwidth_kbps):
    delay_sec = delay_ms / 1000.0
    bw_bps = int(bandwidth_kbps * 1000 / 8) if bandwidth_kbps > 0 else 0

    async def on_connect(reader, writer):
        await handle_connection(reader, writer, target_host, target_port,
                                delay_sec, bw_bps)

    server = await asyncio.start_server(on_connect, "127.0.0.1", listen_port)
    # Signal readiness on stdout (callers wait for this line)
    print(f"PROXY_READY port={listen_port} delay={delay_ms}ms bw={bandwidth_kbps}kbps",
          flush=True)
    async with server:
        await server.serve_forever()


def main():
    parser = argparse.ArgumentParser(
        description="TCP delay proxy for network condition simulation")
    parser.add_argument("--listen-port", type=int, required=True)
    parser.add_argument("--target-host", type=str, default="127.0.0.1")
    parser.add_argument("--target-port", type=int, default=9100)
    parser.add_argument("--delay-ms", type=float, default=0)
    parser.add_argument("--bandwidth-kbps", type=float, default=0,
                        help="Bandwidth limit in kbps (0 = unlimited)")
    args = parser.parse_args()
    asyncio.run(run_proxy(
        args.listen_port, args.target_host, args.target_port,
        args.delay_ms, args.bandwidth_kbps))


if __name__ == "__main__":
    main()

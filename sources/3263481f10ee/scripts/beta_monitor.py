"""Collect operator beta metrics and emit local alerts; no customer contents.

Run under the service supervisor, outside customer artifact directories. Route
stdout to the operator's existing alert collector; this sends no messages itself.
"""
import argparse
import json
import queue
import sys
import threading
import time
from pathlib import Path


def alerts(current, previous):
    result = []
    for field in ("evidence_failures", "storage_errors"):
        if current.get(field, 0) > previous.get(field, 0):
            result.append(field)
    for name in ("owner_pool", "app_pool"):
        pool, before = current.get(name, {}), previous.get(name, {})
        if pool.get("max", 0) and pool.get("in_use", 0) >= pool["max"] * .9:
            result.append(name + ":near_capacity")
        if pool.get("wait_count", 0) > before.get("wait_count", 0):
            result.append(name + ":waiting")
    for account, size in current.get("account_storage_bytes", {}).items():
        if size >= 1024 ** 3 * .9:
            result.append("storage_near_quota:account=" + str(account))
    return result


class Monitor:
    def __init__(self, sources, sink, now):
        self.sink = sink
        self.previous, self.queued, self.last_alerts = {}, {}, {}
        self.received = {source: now for source in sources}

    def record(self, source, line, now):
        if "[beta-metrics] " not in line:
            return
        try:
            current = json.loads(line.split("[beta-metrics] ", 1)[1])
        except ValueError:
            return
        if not isinstance(current, dict):
            return
        warnings = alerts(current, self.previous.get(source, {}))
        if current.get("queued_tasks", 0) and not current.get("running_tasks", 0):
            self.queued.setdefault(source, now)
            if now - self.queued[source] >= 300:
                warnings.append("queue_without_running_tasks:inspect_blocked_states")
        else:
            self.queued.pop(source, None)
        self.sink.write(json.dumps({"source": source, "metrics": current, "alerts": warnings}) + "\n")
        self.sink.flush()
        self.previous[source], self.received[source] = current, now
        if warnings and warnings != self.last_alerts.get(source):
            print(json.dumps({"source": source, "alerts": warnings}), flush=True)
        self.last_alerts[source] = warnings

    def poll(self, now):
        for source, received in self.received.items():
            if now - received > 150 and self.last_alerts.get(source) != ["metrics_stale"]:
                print(json.dumps({"source": source, "alerts": ["metrics_stale"]}), flush=True)
                self.last_alerts[source] = ["metrics_stale"]


def collect(paths, output):
    offsets = {}
    with output.open("a", encoding="utf-8") as sink:
        monitor = Monitor([str(index) for index in range(len(paths))], sink, time.monotonic())
        while True:
            now = time.monotonic()
            for index, path in enumerate(paths):
                source = str(index)
                if path.exists():
                    if path.stat().st_size < offsets.get(source, 0):
                        offsets[source] = 0
                    with path.open(encoding="utf-8", errors="replace") as log:
                        log.seek(offsets.get(source, 0))
                        while True:
                            start = log.tell()
                            line = log.readline()
                            if not line:
                                break
                            if not line.endswith("\n"):
                                log.seek(start)
                                break
                            monitor.record(source, line, now)
                        offsets[source] = log.tell()
            monitor.poll(now)
            time.sleep(2)


def collect_stdin(stream, output):
    messages = queue.Queue(maxsize=1000)

    def read():
        try:
            for line in stream:
                messages.put(line)
        finally:
            messages.put(None)

    threading.Thread(target=read, daemon=True).start()
    with output.open("a", encoding="utf-8") as sink:
        monitor = Monitor(["0"], sink, time.monotonic())
        while True:
            try:
                line = messages.get(timeout=2)
            except queue.Empty:
                line = ""
            if line is None:
                raise RuntimeError("Metrics input closed; the supervisor must restart the collector")
            now = time.monotonic()
            monitor.record("0", line, now)
            monitor.poll(now)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--log", type=Path, action="append")
    source.add_argument("--stdin", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.stdin:
        collect_stdin(sys.stdin, args.output)
    else:
        collect(args.log, args.output)

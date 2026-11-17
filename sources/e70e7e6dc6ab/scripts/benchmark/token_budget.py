"""Conservative, durable admission ledger for a bounded six-run comparison.

This reserves UTF-8 request bytes, a template allowance and the full output cap.
Only confirmed provider usage settles a reservation; uncertain calls retain it.
"""
import json
import os
import threading
from pathlib import Path


class Budget:
    def __init__(self, path, per_run=3_000_000, total=20_000_000):
        self.path = Path(path)
        self.per_run = per_run
        self.total = total
        self.lock = threading.Lock()
        self.rows = [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines()] if self.path.exists() else []

    def reserve(self, run, payload):
        if run not in {f"{product}-{pair}" for product in ("artex", "vulnetic") for pair in range(1, 4)}:
            raise ValueError("unknown comparison run")
        if payload.get("stream") or payload.get("model") != "deepseek-ai/DeepSeek-V4.1-Flash-1017":
            raise ValueError("comparison requires the pinned model and non-streaming usage")
        cap = payload.get("max_tokens")
        if type(cap) is not int or not 1 <= cap <= 4096:
            raise ValueError("an output cap between 1 and 4096 is required")
        amount = len(json.dumps(payload, ensure_ascii=False).encode("utf-8")) + 65_536 + cap
        with self.lock:
            if any(row.get("poisoned") for row in self.rows):
                raise ValueError("usage verification failed; operator review required")
            charges = self.charges()
            reserved = sum(amount for _, amount in charges)
            own = sum(amount for owner, amount in charges if owner == run)
            if reserved + amount > self.total or own + amount > self.per_run:
                raise ValueError("comparison token allowance exhausted")
            ticket = len(self.rows)
            self._append({"ticket": ticket, "run": run, "reserved": amount})
            return ticket

    def charges(self):
        settled = {row["ticket"]: row["actual"] for row in self.rows if type(row.get("actual")) is int and not row.get("poisoned")}
        return [(row["run"], settled.get(row["ticket"], row["reserved"])) for row in self.rows if "reserved" in row]

    def reject(self, ticket, status):
        with self.lock:
            reservation = next(row for row in self.rows if row.get("ticket") == ticket and "reserved" in row)
            self._append({"ticket": ticket, "run": reservation["run"], "actual": None, "http_status": status, "poisoned": status != 429})

    def record(self, ticket, usage):
        with self.lock:
            reservation = next(row for row in self.rows if row.get("ticket") == ticket and "reserved" in row)
            valid = isinstance(usage, dict)
            prompt = usage.get("prompt_tokens") if valid else None
            completion = usage.get("completion_tokens") if valid else None
            valid = type(prompt) is int and prompt >= 0 and type(completion) is int and completion >= 0
            actual = prompt + completion if valid else None
            valid = valid and actual <= reservation["reserved"]
            self._append({"ticket": ticket, "run": reservation["run"], "actual": actual, "poisoned": not valid})
            if not valid:
                raise ValueError("provider usage missing or exceeds conservative reservation")

    def _append(self, row):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as target:
            target.write(json.dumps(row) + "\n")
            target.flush()
            os.fsync(target.fileno())
        self.rows.append(row)

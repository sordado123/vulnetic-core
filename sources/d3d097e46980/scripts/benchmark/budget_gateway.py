"""Loopback-only River gateway for the authorized paired benchmark.

Private JSON configuration supplies upstream credentials and two random tokens.
Only counts are persisted. Run as the operator, outside customer artifact roots.
"""
import argparse
import hmac
import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from token_budget import Budget


def serve(config_path):
    config = json.loads(Path(config_path).read_text(encoding="utf-8"))
    budget = Budget(Path(config_path).with_name("token-ledger.jsonl"))
    state = {"run": None}
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, code, body):
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def authorized(self, token):
            return hmac.compare_digest(self.headers.get("Authorization", ""), "Bearer " + token)

        def do_GET(self):
            if self.path != "/usage" or not self.authorized(config["admin_token"]):
                return self.reply(404, {})
            with budget.lock:
                self.reply(200, {"run": state["run"], "rows": budget.rows, "total_limit": budget.total, "per_run_limit": budget.per_run})

        def do_POST(self):
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 524288:
                    return self.reply(413, {"error": "request size limit"})
                body = json.loads(self.rfile.read(size))
            except (ValueError, json.JSONDecodeError):
                return self.reply(400, {"error": "invalid JSON"})
            if self.path == "/control" and self.authorized(config["admin_token"]):
                run = body.get("run")
                if run is not None and run not in {f"{product}-{pair}" for product in ("artex", "vulnetic") for pair in range(1, 4)}:
                    return self.reply(400, {"error": "unknown run"})
                with lock:
                    state["run"] = run
                return self.reply(200, {"run": run})
            if self.path != "/v1/chat/completions" or not self.authorized(config["client_token"]):
                return self.reply(404, {})
            # Serialize calls so an operator run switch cannot misattribute usage.
            with lock:
                try:
                    ticket = budget.reserve(state["run"], body)
                except ValueError as exc:
                    return self.reply(402, {"error": {"message": str(exc), "code": "insufficient_quota"}})
                request = urllib.request.Request(config["base_url"].rstrip("/") + "/chat/completions", data=json.dumps(body).encode(), headers={"Authorization": "Bearer " + config["api_key"], "Content-Type": "application/json"})
                try:
                    with urllib.request.urlopen(request, timeout=90) as response:
                        data = response.read(8 * 1024 * 1024 + 1)
                    if len(data) > 8 * 1024 * 1024:
                        raise ValueError("response limit")
                    result = json.loads(data)
                    budget.record(ticket, result.get("usage"))
                except urllib.error.HTTPError as exc:
                    # A rate rejection retains its full reservation but can retry.
                    budget.reject(ticket, exc.code)
                    return self.reply(429 if exc.code == 429 else 502, {"error": {"message": "upstream rejected request", "status": exc.code}})
                except Exception as exc:
                    # A failed or canceled upstream may have billed tokens.
                    if not any(row.get("ticket") == ticket and "actual" in row for row in budget.rows):
                        try:
                            budget.record(ticket, None)
                        except ValueError:
                            pass
                    print(json.dumps({"error_type": type(exc).__name__, "ticket": ticket}), flush=True)
                    return self.reply(502, {"error": {"message": "usage verification failed; operator review required"}})
                self.reply(200, result)

    ThreadingHTTPServer(("127.0.0.1", config.get("port", 3059)), Handler).serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("config")
    serve(parser.parse_args().config)

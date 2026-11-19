import unittest
import contextlib
import io
import json
import tempfile
from pathlib import Path

from beta_monitor import Monitor, alerts, collect_stdin


class MonitorTest(unittest.TestCase):
    def test_count_alerts_and_counter_reset(self):
        current = {"evidence_failures": 1, "storage_errors": 1, "app_pool": {"max": 20, "in_use": 18, "wait_count": 2}, "account_storage_bytes": {"2": 1024 ** 3}}
        self.assertEqual(set(alerts(current, {})), {"evidence_failures", "storage_errors", "app_pool:near_capacity", "app_pool:waiting", "storage_near_quota:account=2"})
        self.assertEqual(alerts({}, current), [])
        self.assertEqual(alerts({"app_pool": {"max": 20, "in_use": 1, "wait_count": 2}}, current), [])

    def test_stale_queue_and_recovery(self):
        sink, notifications = io.StringIO(), io.StringIO()
        monitor = Monitor(["0"], sink, 0)
        with contextlib.redirect_stdout(notifications):
            monitor.record("0", "[beta-metrics] not-json", 150)
            monitor.poll(151)
            monitor.poll(152)
            self.assertEqual(len(notifications.getvalue().splitlines()), 1)
            monitor.record("0", '[beta-metrics] {"queued_tasks":1}', 153)
            monitor.record("0", '[beta-metrics] {"queued_tasks":1}', 454)
            monitor.record("0", '[beta-metrics] {"running_tasks":1}', 455)
            monitor.record("0", '[beta-metrics] {"queued_tasks":1}', 456)
            monitor.poll(607)
        records = [json.loads(line) for line in sink.getvalue().splitlines()]
        self.assertEqual(records[1]["alerts"], ["queue_without_running_tasks:inspect_blocked_states"])
        self.assertEqual(records[2]["alerts"], [])
        self.assertEqual(records[3]["alerts"], [])
        self.assertEqual(json.loads(notifications.getvalue().splitlines()[-1])["alerts"], ["metrics_stale"])

    def test_stdin_eof_fails_for_supervisor_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "metrics.jsonl"
            with self.assertRaisesRegex(RuntimeError, "Metrics input closed"):
                collect_stdin(io.StringIO('[beta-metrics] {"running_tasks":0}\n'), output)
            self.assertEqual(json.loads(output.read_text())["metrics"], {"running_tasks": 0})


if __name__ == "__main__":
    unittest.main()

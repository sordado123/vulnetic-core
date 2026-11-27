import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from token_budget import Budget


class TokenBudgetTest(unittest.TestCase):
    def test_only_confirmed_usage_settles_reservation(self):
        payload = {"model": "deepseek-ai/DeepSeek-V4.1-Flash-1017", "stream": False, "max_tokens": 4096}
        with tempfile.TemporaryDirectory() as folder:
            budget = Budget(Path(folder) / "ledger", per_run=80_000, total=80_000)
            first = budget.reserve("artex-1", payload)
            with self.assertRaises(ValueError):
                budget.reserve("artex-1", payload)
            budget.record(first, {"prompt_tokens": 10, "completion_tokens": 2})
            second = budget.reserve("artex-1", payload)
            budget.reject(second, 429)
            self.assertEqual(budget.charges()[0], ("artex-1", 12))
            self.assertGreater(budget.charges()[1][1], 69_000)
            with self.assertRaises(ValueError):
                budget.reserve("artex-1", payload)

    def test_durable_concurrent_admission_and_usage_fail_closed(self):
        payload = {"model": "deepseek-ai/DeepSeek-V4.1-Flash-1017", "stream": False, "max_tokens": 4096, "messages": []}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "ledger.jsonl"
            budget = Budget(path, per_run=150_000, total=150_000)
            def attempt(_):
                try:
                    return budget.reserve("artex-1", payload)
                except ValueError:
                    return None
            with ThreadPoolExecutor(max_workers=8) as pool:
                tickets = [ticket for ticket in pool.map(attempt, range(8)) if ticket is not None]
            self.assertEqual(len(tickets), 2)
            budget = Budget(path, per_run=150_000, total=150_000)
            with self.assertRaises(ValueError):
                budget.reserve("vulnetic-1", payload)
            budget.record(tickets[0], {"prompt_tokens": 10, "completion_tokens": 2})
            with self.assertRaises(ValueError):
                budget.record(tickets[1], None)
            with self.assertRaises(ValueError):
                Budget(path).reserve("vulnetic-1", payload)

    def test_unbounded_wrong_model_and_unknown_run_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            budget = Budget(Path(folder) / "ledger")
            for payload in [{}, {"model": "other", "max_tokens": 4096}, {"model": "deepseek-ai/DeepSeek-V4.1-Flash-1017", "max_tokens": 4096, "stream": True}]:
                with self.assertRaises(ValueError):
                    budget.reserve("artex-1", payload)
            with self.assertRaises(ValueError):
                budget.reserve("artex-4", {})


if __name__ == "__main__":
    unittest.main()

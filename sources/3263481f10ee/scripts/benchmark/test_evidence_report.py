import json
import pathlib
import tempfile
import types
import unittest

import run_bench


class EvidenceReportTests(unittest.TestCase):
    def test_llm_match_is_not_exported_as_confirmation(self):
        args = types.SimpleNamespace(gt_version="fixture", subject_model="subject", judge_model="judge", corpus_type="image")
        result = {"scanner_findings_total": 1, "detected": 1, "ground_truth_total": 1,
                  "detection_rate": 1, "detection_rate_wilson95": [0.2, 1], "gate_totals_over_detected": {},
                  "mean_gate_score_of_6": 6, "discovery_candidates": [], "precision_bounds_until_verified": [1, 1],
                  "invalid_findings_excluded": []}
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory)
            run_bench.write_report(path, "fixture", args, {"id": 1}, "done", [], [], result)
            exported = json.loads((path / "results.json").read_text())["result"]
            self.assertIsNone(exported["confirmed_findings"])
            self.assertFalse(exported["superiority_claim_allowed"])
            self.assertIn("Unverified screening", (path / "report.md").read_text())


if __name__ == "__main__":
    unittest.main()

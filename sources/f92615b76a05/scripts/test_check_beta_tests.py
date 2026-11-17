import unittest
from check_beta_tests import REQUIRED, check


class SecurityGateTest(unittest.TestCase):
    def test_requires_actual_pass_events(self):
        events = [{"Test": name, "Action": "pass"} for name in sorted(REQUIRED | {"TestBetaFixture"})]
        self.assertEqual(check(events), [])
        for missing in REQUIRED:
            with self.subTest(missing=missing):
                self.assertTrue(check(event for event in events if event["Test"] != missing))
        self.assertTrue(check(events + [{"Test": "TestBetaFixture/subtest", "Action": "skip"}]))
        self.assertTrue(check(events + [{"Test": "TestInterceptFilterHTTP", "Action": "fail"}]))


if __name__ == "__main__":
    unittest.main()

import unittest
import hashlib
import json
import tempfile
from pathlib import Path
from review_replays import execution_signals, signals, proofs, review

class ReviewTest(unittest.TestCase):
    def test_description_alone_and_wrong_destination_do_not_confirm(self):
        self.assertEqual(execution_signals('report_finding', 'confidential acquisitions.md'), set())
        self.assertEqual(execution_signals('curl http://other/ftp/acquisitions.md', 'confidential'), set())
        self.assertEqual(execution_signals('curl http://127.0.0.1:3037/ftp/acquisitions.md', 'confidential'), {'GT-004'})
        self.assertEqual(execution_signals('curl http://127.0.0.1:3037/ftp/acquisitions.md', 'not found'), set())
        self.assertEqual(signals('generic finding without reproduction details'), set())

    def test_proof_attribution_and_integrity_fail_closed(self):
        proof = {'id': 1, 'task_id': 7, 'run_id': 'run-7', 'tool': 'Bash', 'input': {}, 'output': 'observed output', 'sha256': hashlib.sha256(b'observed output').hexdigest()}
        artifact = {'run': 'vulnetic-1', 'task': {'id': 7}, 'proofs': {'proofs': [proof]}}
        self.assertEqual(len(list(proofs(Path('.'), artifact))), 1)
        for changes in ({'task_id': 8}, {'run_id': ''}, {'truncated': True}, {'output': 'changed'}, {'tool': 'report_finding'}):
            with self.subTest(changes=changes):
                artifact['proofs']['proofs'] = [dict(proof, **changes)]
                self.assertEqual(list(proofs(Path('.'), artifact)), [])

    def test_every_candidate_gets_a_reason_without_a_confirmation(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            (directory / 'independent-replay.json').write_text(json.dumps({'results': []}))
            for product in ('artex', 'vulnetic'):
                for pair in range(1, 4):
                    run = f'{product}-{pair}'
                    artifact = {'run': run, 'task': {'id': 7, 'exploration_id': 1}, 'details': [{'finding_id': 'candidate-1', 'task_id': 7, 'summary': 'uncovered claim'}, {'finding_id': 'candidate-2', 'task_id': 8, 'summary': 'uncovered claim'}]}
                    (directory / (run + '.json')).write_text(json.dumps(artifact))
            rows = review(directory)
            self.assertEqual(len(rows), 6)
            for row in rows:
                self.assertEqual(row['inconclusive'], 2)
                self.assertIsNone(row['confirmed_candidates'])
                self.assertIsNone(row['confirmed_false_positives'])
                self.assertEqual([r['reason'] for r in row['reviews']], ['outside_automated_review_coverage', 'task_mismatch'])
                self.assertTrue(all(r['confirmation'] == 'not_assessed' for r in row['reviews']))

if __name__ == '__main__':
    unittest.main()

"""Conservative replay review. Unsupported evidence stays inconclusive.

This produces private identifiers and aggregate metrics, never finding contents.
It supports only the three HTTP oracles in juice_oracles.py, not the whole corpus.
Matching markers are triage hints, never a confirmation or a false-positive verdict.
"""
import argparse
import hashlib
import json
import re
import tarfile
from pathlib import Path


def signals(text):
    text = text.lower()
    result = set()
    if "acquisitions.md" in text and ("confidential" in text or "sensitive" in text):
        result.add("GT-004")
    if "/rest/user/login" in text and any(word in text for word in ("sql injection", "1=1", "1 = 1", "tautology")):
        result.add("GT-001")
    if "sqlite_error" in text and any(word in text for word in ("stack", "internal path", "disclosure", "/juice-shop/")):
        result.add("GT-006")
    return result


def execution_signals(command, output):
    # Model explanations or a recorded report_finding call cannot confirm execution.
    if "3037" not in command or not any(tool in command for tool in ("curl", "requests", "urllib")):
        return set()
    result = signals(command + "\n" + output)
    if "confidential" not in output.lower():
        result.discard("GT-004")
    if not re.search(r'"(?:token|authentication)"\s*:', output):
        result.discard("GT-001")
    if "SQLITE_ERROR" not in output:
        result.discard("GT-006")
    return result


def proofs(directory, artifact):
    task = artifact['task']
    if artifact['run'].startswith('vulnetic'):
        for proof in artifact.get('proofs', {}).get('proofs', []):
            if str(proof.get('task_id')) != str(task['id']) or proof.get('truncated') or not proof.get('run_id'):
                continue
            if proof.get('tool') != 'Bash' or hashlib.sha256(proof['output'].encode()).hexdigest() != proof['sha256']:
                continue
            yield str(proof['id']), json.dumps(proof['input']), proof['output']
        return
    archive = directory / (artifact['run'] + '-reference-data.tar.gz')
    if not archive.exists():
        return
    with tarfile.open(archive) as source:
        for member in source.getmembers():
            if not member.isfile() or not member.name.startswith('data/transcripts/exp' + str(task['exploration_id']) + '-') or not member.name.endswith('.jsonl'):
                continue
            calls = {}
            for line in source.extractfile(member):
                message = json.loads(line).get('message', {})
                for block in message.get('content', []):
                    if block.get('type') == 'tool_use' and block.get('name') == 'Bash':
                        calls[block['id']] = json.dumps(block.get('input', {}))
                    if block.get('type') == 'tool_result' and not block.get('is_error') and block.get('tool_use_id') in calls:
                        output = json.dumps(block.get('content', []), ensure_ascii=False)
                        yield member.name + ':' + block['tool_use_id'], calls[block['tool_use_id']], output.replace('\\"', '"')


def review(directory):
    replay = json.loads((directory / 'independent-replay.json').read_text(encoding='utf-8'))
    reproduced = {row['oracle'] for row in replay['results'] if row['reproduced']}
    results = []
    for product in ('artex', 'vulnetic'):
        for pair in range(1, 4):
            artifact = json.loads((directory / f'{product}-{pair}.json').read_text(encoding='utf-8'))
            evidence = {}
            for identifier, command, output in proofs(directory, artifact):
                for oracle in execution_signals(command, output) & reproduced:
                    evidence.setdefault(oracle, []).append(identifier)
            findings = []
            unique = set()
            for finding in artifact['details']:
                eligible = signals(str(finding.get('summary', '')) + '\n' + str(finding.get('evidence', '')))
                owned = str(finding.get('task_id')) == str(artifact['task']['id'])
                supported = sorted(eligible & evidence.keys()) if owned else []
                if not owned:
                    reason = 'task_mismatch'
                elif not eligible:
                    reason = 'outside_automated_review_coverage'
                elif not eligible & reproduced:
                    reason = 'independent_replay_did_not_confirm_condition'
                elif not supported:
                    reason = 'no_compatible_execution_record'
                else:
                    reason = 'candidate_to_proof_association_requires_review'
                unique.update(supported)
                findings.append({'finding_id': finding.get('finding_id'), 'outcome': 'compatible_execution_and_replay' if supported else 'inconclusive', 'reason': reason, 'confirmation': 'not_assessed', 'oracles': supported, 'proof_ids': {key: evidence[key] for key in supported}})
            results.append({'run': artifact['run'], 'candidates': len(findings), 'compatible_candidates': sum(bool(row['oracles']) for row in findings), 'distinct_reproduced_oracles': len(unique), 'evaluated_oracles': len(reproduced), 'inconclusive': sum(not row['oracles'] for row in findings), 'confirmed_candidates': None, 'confirmed_false_positives': None, 'reviews': findings})
    return results


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    results = review(args.directory)
    (args.directory / 'replay-review.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    print(json.dumps([{key: value for key, value in row.items() if key != 'reviews'} for row in results]))

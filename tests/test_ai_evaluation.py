import json
from tools.evaluate_local_ai import evaluate
import pytest


def record(tmp_path, name, sha, state, verdict=None):
    path = tmp_path / name
    path.write_text(json.dumps({'state': state, 'sha256': sha, 'result': {
        'sha256': sha, 'verdict': verdict, 'ai_model_ran': state == 'complete',
        'processing_location': 'local', 'model': 'fixture', 'model_digest': 'digest'}}))
    return str(path)


def test_evaluation_counts_abstentions_and_failures_in_coverage(tmp_path):
    entries = [
        {'report': record(tmp_path, 'a.json', 'a'*64, 'complete', 'suspicious'), 'label': 'malicious'},
        {'report': record(tmp_path, 'b.json', 'b'*64, 'complete', 'no_indicators'), 'label': 'benign'},
        {'report': record(tmp_path, 'c.json', 'c'*64, 'complete', 'inconclusive'), 'label': 'malicious'},
        {'report': record(tmp_path, 'd.json', 'd'*64, 'failed'), 'label': 'benign'},
    ]
    result = evaluate(entries, tmp_path, 'independent analyst labels')
    assert result['total'] == 4 and result['decided'] == 2
    assert result['abstained'] == 1 and result['failed_or_unfinished'] == 1
    assert result['decision_coverage'] == .5
    assert result['malicious_recall_all_labeled'] == .5
    assert result['accuracy_on_decisions'] == 1
    assert result['correct_fraction_all_labeled'] == .5


def test_duplicate_hashes_cannot_inflate_metrics(tmp_path):
    path = record(tmp_path, 'a.json', 'a'*64, 'complete', 'suspicious')
    with pytest.raises(ValueError, match='Duplicate'):
        evaluate([{'report': path, 'label': 'malicious'}] * 2, tmp_path, 'Independent labels')


def test_ground_truth_and_real_local_inference_are_required(tmp_path):
    path = record(tmp_path, 'a.json', 'a'*64, 'complete', 'no_indicators')
    with pytest.raises(ValueError, match='label'):
        evaluate([{'report': path, 'label': 'model said safe'}], tmp_path, 'Model output')
    raw = json.loads(open(path).read()); raw['result']['ai_model_ran'] = False
    with open(path, 'w') as output:
        json.dump(raw, output)
    with pytest.raises(ValueError, match='inference'):
        evaluate([{'report': path, 'label': 'benign'}], tmp_path, 'Independent labels')

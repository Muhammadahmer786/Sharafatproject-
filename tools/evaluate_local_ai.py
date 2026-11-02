"""Evaluate exported AI reports against independent labels; never opens or executes samples.

Manifest: {"label_source":"...", "cases":[{"report":"export.json", "label":"benign|malicious"}]}.
Use held-out authorized samples with independent ground truth. This tool cannot
verify how labels were obtained; recording a source does not validate a dataset.
"""
import argparse
import json
from pathlib import Path
import re


def evaluate(entries, directory, label_source):
    if not isinstance(label_source, str) or not label_source.strip():
        raise ValueError('Record the independent label source.')
    if not isinstance(entries, list) or not 1 <= len(entries) <= 10000:
        raise ValueError('Provide between 1 and 10000 labeled cases.')
    counts = dict(total=len(entries), decided=0, abstained=0, failed_or_unfinished=0,
                  true_positive=0, true_negative=0, false_positive=0, false_negative=0,
                  labeled_malicious=0, labeled_benign=0)
    seen, models = set(), set()
    for entry in entries:
        if entry.get('label') not in ('benign', 'malicious'):
            raise ValueError('Each case needs an independent benign or malicious label.')
        label = entry['label']; counts['labeled_' + label] += 1
        path = (Path(directory) / entry['report']).resolve()
        if path.stat().st_size > 2 * 1024 * 1024:
            raise ValueError('Report exceeds the 2 MiB evaluation bound.')
        report = json.loads(path.read_text(encoding='utf-8'))
        sha = report.get('sha256', '')
        if not isinstance(sha, str) or not re.fullmatch('[a-fA-F0-9]{64}', sha):
            raise ValueError('Each report must identify its sample by SHA-256.')
        sha = sha.lower()
        if sha in seen:
            raise ValueError('Duplicate sample SHA-256 would inflate the evaluation.')
        seen.add(sha)
        if report.get('state') != 'complete':
            counts['failed_or_unfinished'] += 1
            continue
        result = report.get('result', {})
        if (result.get('ai_model_ran') is not True or result.get('processing_location') != 'local'
                or result.get('sha256', '').lower() != sha or not result.get('model_digest')):
            raise ValueError('Completed reports must record local inference and matching provenance.')
        models.add((result.get('model', ''), result['model_digest']))
        verdict = result.get('verdict')
        if verdict == 'inconclusive':
            counts['abstained'] += 1
            continue
        if verdict not in ('suspicious', 'no_indicators'):
            raise ValueError('Unsupported triage verdict.')
        counts['decided'] += 1
        positive = verdict == 'suspicious'
        correct = positive == (label == 'malicious')
        counts[('true_' if correct else 'false_') + ('positive' if positive else 'negative')] += 1
    def fraction(numerator, denominator):
        return numerator / denominator if denominator else None
    tp, tn, fp, fn = (counts[key] for key in ('true_positive', 'true_negative', 'false_positive', 'false_negative'))
    return dict(counts, label_source=label_source.strip(), models=[{'model': m, 'digest': d} for m, d in sorted(models)],
                decision_coverage=fraction(counts['decided'], counts['total']),
                precision=fraction(tp, tp + fp),
                malicious_recall_all_labeled=fraction(tp, counts['labeled_malicious']),
                false_positive_rate_all_benign=fraction(fp, counts['labeled_benign']),
                accuracy_on_decisions=fraction(tp + tn, counts['decided']),
                correct_fraction_all_labeled=fraction(tp + tn, counts['total']),
                limitations=['Suspicious maps to positive; no_indicators maps to negative solely for this evaluation.',
                             'Abstentions and unfinished analyses remain in total coverage and all-labeled denominators.',
                             'Ground-truth independence, sample licensing and dataset representativeness require human validation.',
                             'Metrics apply only to this dataset, model digest and prompt implementation.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source = json.loads(args.manifest.read_text(encoding='utf-8'))
    result = evaluate(source['cases'], args.manifest.parent, source['label_source'])
    with args.output.open('x', encoding='utf-8') as output:
        json.dump(result, output, indent=2)
    print(f'Evaluated {result["total"]} unique labeled samples; report saved to {args.output}.')


if __name__ == '__main__':
    main()

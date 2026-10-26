"""CIC-IDS2017 training with disjoint capture-day and unseen-family evaluation."""
import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

from security_app.detection import FIELDS, SCHEMA, flow_rules
from src.model import StandardLogisticRegression
from src.metrics import binary_metrics

COLUMNS = ['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Destination Port', 'Label']


def load_data(directory, cap=1500):
    parts, audit = [], []
    for file in sorted(Path(directory).glob('*.csv')):
        chunks, total, valid = [], 0, 0
        for chunk in pd.read_csv(file, encoding='utf-8', encoding_errors='replace', chunksize=100000,
                                 usecols=lambda c: c.strip() in COLUMNS):
            chunk.columns = chunk.columns.str.strip()
            if set(COLUMNS) - set(chunk.columns):
                raise ValueError(f'Missing required CIC columns in {file.name}')
            total += len(chunk)
            numeric = chunk[COLUMNS[:-1]].apply(pd.to_numeric, errors='coerce')
            numeric.columns = FIELDS
            numeric.duration_seconds /= 1e6
            good = np.isfinite(numeric).all(axis=1) & (numeric >= 0).all(axis=1)
            good &= numeric.destination_port.le(65535) & numeric.le(1e12).all(axis=1)
            good &= numeric[FIELDS[1:]].mod(1).eq(0).all(axis=1)
            numeric['label'] = chunk.Label.astype(str).str.strip()
            numeric = numeric.loc[good]
            valid += len(numeric)
            # Deterministic hash priorities make sampling independent of chunk boundaries.
            numeric['priority'] = pd.util.hash_pandas_object(numeric[FIELDS + ['label']], index=False)
            chunks.append(numeric.sort_values('priority').groupby('label', group_keys=False).head(cap))
        if not chunks:
            continue
        frame = pd.concat(chunks).sort_values('priority').groupby('label', group_keys=False).head(cap)
        frame['source'] = file.name
        parts.append(frame)
        audit.append({'file': file.name, 'rows_read': total, 'valid_rows': valid, 'sampled_rows': len(frame)})
    if not parts:
        raise ValueError('No CIC CSV files found')
    frame = pd.concat(parts, ignore_index=True)
    # Identical model inputs cannot appear in more than one partition, even with conflicting labels.
    before = len(frame)
    frame = frame.drop_duplicates(FIELDS, keep='first').copy()
    frame['attack'] = frame.label.str.upper().ne('BENIGN').astype(int)
    return frame, {'files': audit, 'duplicate_feature_rows_removed': before - len(frame)}


def fit(frame):
    if frame.attack.nunique() != 2:
        raise ValueError('Training partition must contain both benign and attack traffic')
    return StandardLogisticRegression(epochs=1000).fit(np.log1p(frame[FIELDS].to_numpy(float)), frame.attack.to_numpy())


def evaluate(model, frame):
    if frame.empty:
        return {'status': 'not available: empty test partition'}
    predictions = model.predict(np.log1p(frame[FIELDS].to_numpy(float)))
    result = binary_metrics(frame.attack.to_numpy(), predictions)
    result['false_positive_rate'] = result['false_positive'] / max(1, result['false_positive'] + result['true_negative'])
    result['false_negative_rate'] = result['false_negative'] / max(1, result['false_negative'] + result['true_positive'])
    result['rows'] = len(frame)
    result['attack_labels'] = {}
    for label in sorted(frame.label.unique()):
        mask = frame.label.eq(label).to_numpy()
        result['attack_labels'][label] = {'rows': int(mask.sum()), 'predicted_attack_fraction': float(predictions[mask].mean())}
    result['confusion_matrix_order'] = 'TN, FP, FN, TP; attack is the positive class'
    return result


def compare_rules(model, frame):
    x, y = frame[FIELDS].to_numpy(float), frame.attack.to_numpy()
    ml = model.predict(np.log1p(x))
    rules = np.array([bool(flow_rules(row)) for row in x], dtype=int)
    return {'ml_only': binary_metrics(y, ml), 'rules_only': binary_metrics(y, rules),
            'ml_or_rules': binary_metrics(y, np.maximum(ml, rules)),
            'note': 'OR is the application alert policy, not a newly trained or calibrated classifier.'}


def explanation_check(model, frame):
    x = frame[FIELDS].to_numpy(float)[:200]
    original = np.array([model.local_contributions(np.log1p(row)) for row in x])
    changed = x.copy()
    changed[:, :3] *= 1.05
    changed[:, 1:3] = np.rint(changed[:, 1:3])
    perturbed = np.array([model.local_contributions(np.log1p(row)) for row in changed])
    score = original.sum(axis=1) + model.intercept_
    reconstructed = 1 / (1 + np.exp(-np.clip(score, -35, 35)))
    return {'rows': len(x), 'max_probability_reconstruction_error': float(np.max(np.abs(reconstructed - model.predict_proba(np.log1p(x))))),
            'top_feature_unchanged_fraction': float((np.abs(original).argmax(axis=1) == np.abs(perturbed).argmax(axis=1)).mean()),
            'method': 'Increase duration and packet counts by 5%, round packet counts; keep destination port fixed.',
            'limitation': 'A small deterministic sensitivity check, not proof of explanation correctness, causality or analyst usefulness.'}


def train(directory, output, cap=1500):
    frame, audit = load_data(directory, cap)
    # Friday never enters training, preprocessing, or the unseen-family experiment.
    is_friday = frame.source.str.startswith('Friday')
    development, day_test = frame.loc[~is_friday].copy(), frame.loc[is_friday].copy()
    if day_test.empty:
        raise ValueError('Friday CSVs required for the independent capture-day test')
    rng = np.random.default_rng(42)
    test_ids = []
    for _, group in development.groupby('label'):
        ids = rng.permutation(group.index)
        if len(ids) > 1:
            test_ids.extend(ids[:max(1, int(.25 * len(ids)))])
    test = development.loc[test_ids]
    training = development.drop(test_ids)
    assert set(training.index).isdisjoint(test.index)
    assert set(training.index).isdisjoint(day_test.index)
    model = fit(training)
    unseen_mask = development.label.str.contains('Web Attack', case=False, regex=False)
    unseen_train = training.loc[~training.label.str.contains('Web Attack', case=False, regex=False)]
    unseen_test = pd.concat([development.loc[unseen_mask], test.loc[test.attack.eq(0)]])
    unseen = evaluate(fit(unseen_train), unseen_test) if unseen_mask.any() else {'status': 'No Web Attack samples available'}
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    partitions = frame[['source', 'label']].copy()
    partitions['feature_hash'] = pd.util.hash_pandas_object(frame[FIELDS], index=False)
    partitions['partition'] = 'friday-test'
    partitions.loc[training.index, 'partition'] = 'train'
    partitions.loc[test.index, 'partition'] = 'in-distribution-test'
    partitions.to_csv(output / 'partitions.csv', index=False)
    np.savez(output / 'model.npz', **{n: getattr(model, n) for n in ['mean_', 'scale_', 'coef_', 'intercept_']})
    metadata = {'schema': SCHEMA, 'features': FIELDS, 'transform': 'log1p, then training-only z-score',
                'dataset': 'CIC-IDS2017 user-provided MachineLearningCVE CSVs', 'seed': 42, 'threshold': .5,
                'training_rows': len(training), 'training_sources': sorted(training.source.unique()),
                'scope': 'Four-feature binary logistic baseline; no attack-family classifier; not production validated.'}
    (output / 'metadata.json').write_text(json.dumps(metadata, indent=2))
    report = {'metadata': metadata, 'audit': audit, 'in_distribution_test': evaluate(model, test),
              'friday_capture_day_test': evaluate(model, day_test), 'held_out_web_attack_test': unseen,
              'comparative_validation': compare_rules(model, day_test),
              'explanation_sensitivity': explanation_check(model, test),
              'threshold_03_friday': binary_metrics(day_test.attack.to_numpy(), model.predict(np.log1p(day_test[FIELDS].to_numpy(float)), threshold=.3)),
              'partition_sizes': {'train': len(training), 'test': len(test), 'friday': len(day_test)},
              'limitations': ['Sampling changes prevalence: reported precision is not a deployment estimate.',
                             'Friday is a same-dataset domain-shift test, not an independent external dataset.',
                             'Four counts/duration/port features do not identify account takeover or specific attack families.',
                             'Local linear contributions explain the model, not causal reasons or attacker intent.',
                             'Zeek and CIC flow boundaries differ; live Zeek scores are experimental.',
                             'No SHAP/LIME, automatic blocking, or exact attacker location is claimed.']}
    (output / 'evaluation.json').write_text(json.dumps(report, indent=2, default=lambda x: x.item()))
    rows = ['# Integrated prototype: measured evaluation', '', '| Experiment | Rows | Accuracy | Precision | Recall | F1 | FP | FN |', '|---|---:|---:|---:|---:|---:|---:|---:|']
    for name in ['in_distribution_test', 'friday_capture_day_test', 'held_out_web_attack_test']:
        r = report[name]
        if 'f1' in r:
            rows.append(f"| {name} | {r['rows']} | {r['accuracy']:.3f} | {r['precision']:.3f} | {r['recall']:.3f} | {r['f1']:.3f} | {r['false_positive']} | {r['false_negative']} |")
    rows.extend(['', '## Interpretation', '', *['- ' + s for s in report['limitations']]])
    rows.extend(['', '## Same-record comparison on held-out Friday', '', '| Policy | Precision | Recall | F1 | FP | FN |', '|---|---:|---:|---:|---:|---:|'])
    for name, r in report['comparative_validation'].items():
        if isinstance(r, dict):
            rows.append(f"| {name} | {r['precision']:.3f} | {r['recall']:.3f} | {r['f1']:.3f} | {r['false_positive']} | {r['false_negative']} |")
    rows.extend(['', '## Explanation sensitivity', '', json.dumps(report['explanation_sensitivity'], indent=2)])
    (output / 'RESULTS.md').write_text('\n'.join(rows) + '\n')
    print(json.dumps(report, indent=2, default=lambda x: x.item()))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--data-dir', required=True)
    parser.add_argument('--output', default='instance/model')
    parser.add_argument('--per-label-per-file', type=int, default=1500)
    args = parser.parse_args()
    train(args.data_dir, args.output, args.per_label_per_file)


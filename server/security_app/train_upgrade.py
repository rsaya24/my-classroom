"""Validation-selected interpretable nonlinear candidate; Friday is evaluation only."""
import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.tree import DecisionTreeClassifier

from security_app.detection import FIELDS, SCHEMA
from security_app.train import load_data
from security_app.tree_model import PortableTree, export_tree, features
from src.metrics import binary_metrics
from src.model import StandardLogisticRegression


def split(frame, fraction, seed):
    rng = np.random.default_rng(seed)
    selected = []
    for _, group in frame.groupby('label'):
        if len(group) >= 3:
            selected.extend(rng.permutation(group.index)[:max(1, int(len(group) * fraction))])
    return frame.drop(selected), frame.loc[selected]


def metrics(y, p):
    result = binary_metrics(np.asarray(y), np.asarray(p))
    result['false_positive_rate'] = result['false_positive'] / max(1, result['false_positive'] + result['true_negative'])
    result['false_negative_rate'] = result['false_negative'] / max(1, result['false_negative'] + result['true_positive'])
    result['balanced_accuracy'] = 1 - (result['false_positive_rate'] + result['false_negative_rate']) / 2
    return result


def train(data_dir, output, cap=1500):
    frame, audit = load_data(data_dir, cap)
    friday = frame.loc[frame.source.str.startswith('Friday')]
    development = frame.loc[~frame.source.str.startswith('Friday')]
    pool, test = split(development, .25, 42)
    training, validation = split(pool, .25, 43)
    if any(part.empty or part.attack.nunique() != 2 for part in [training, validation, test, friday]):
        raise ValueError('Training, validation and both tests must contain both classes')
    xtrain, ytrain = features(training[FIELDS]), training.attack.to_numpy()
    candidates = []
    for depth in [4, 8, 12]:
        for leaves in [10, 30]:
            clf = DecisionTreeClassifier(max_depth=depth, min_samples_leaf=leaves,
                                         class_weight='balanced', random_state=42).fit(xtrain, ytrain)
            result = metrics(validation.attack, clf.predict(features(validation[FIELDS])))
            candidates.append((result['balanced_accuracy'], -depth, leaves, clf, result))
    selected = max(candidates, key=lambda c: c[:3])
    classifier = selected[3]  # Freeze before evaluating either test; no refit on validation or test.
    portable = PortableTree(export_tree(classifier))
    baseline = StandardLogisticRegression(epochs=1000).fit(np.log1p(training[FIELDS].to_numpy()), ytrain)
    results = {}
    for name, part in [('validation', validation), ('same_distribution_test', test), ('friday_test', friday)]:
        raw = part[FIELDS].to_numpy(float)
        predicted = portable.predict_proba(raw) >= .5
        assert np.array_equal(predicted, classifier.predict(features(raw)))
        results[name] = {'rows': len(part), 'tree': metrics(part.attack, predicted),
                         'linear_same_training_rows': metrics(part.attack, baseline.predict(np.log1p(raw))),
                         'per_label': {label: {'rows': int(mask.sum()), 'predicted_attack_fraction': float(predicted[mask].mean())}
                                       for label in sorted(part.label.unique()) for mask in [part.label.eq(label).to_numpy()]}}
    unseen_train = training.loc[~training.label.str.contains('Web Attack', case=False, regex=False)]
    unseen_test = pd.concat([development.loc[development.label.str.contains('Web Attack', case=False, regex=False)], test.loc[test.attack.eq(0)]])
    unseen = DecisionTreeClassifier(**classifier.get_params()).fit(features(unseen_train[FIELDS]), unseen_train.attack)
    results['unseen_web_attacks_with_benign_controls'] = metrics(unseen_test.attack, unseen.predict(features(unseen_test[FIELDS])))
    output = Path(output)
    if output.exists() and any(output.iterdir()):
        raise ValueError('Use a new output directory; previous model artifacts are preserved')
    output.mkdir(parents=True, exist_ok=True)
    (output / 'tree.json').write_text(json.dumps(portable.data))
    metadata = {'schema': SCHEMA, 'algorithm': 'decision-tree-v1', 'features': FIELDS,
                'dataset': 'CIC-IDS2017 supplied MachineLearningCVE CSVs', 'threshold': .5,
                'training_rows': len(training), 'training_sources': sorted(training.source.unique()),
                'transform': 'Raw four features plus deterministic packet rate and backward fraction',
                'scope': 'Validation-selected binary decision tree; no production reliability claim',
                'max_depth': classifier.max_depth, 'min_samples_leaf': classifier.min_samples_leaf,
                'selection': 'Maximum validation balanced accuracy; Friday and test excluded',
                'validation_rows': len(validation), 'seed': 42}
    (output / 'metadata.json').write_text(json.dumps(metadata, indent=2))
    manifest = frame[['source', 'label']].copy()
    manifest['feature_hash'] = pd.util.hash_pandas_object(frame[FIELDS], index=False)
    manifest['partition'] = 'friday-test'
    for name, part in [('train', training), ('validation', validation), ('test', test)]:
        manifest.loc[part.index, 'partition'] = name
    assert manifest.feature_hash.is_unique
    manifest.to_csv(output / 'partitions.csv', index=False)
    report = {'metadata': metadata, 'audit': audit, 'results': results,
              'candidates_validation_only': [{'depth': -d, 'min_samples_leaf': leaf, 'metrics': m} for _, d, leaf, _, m in candidates],
              'cautions': ['Friday was examined in earlier work: this is a development comparison, not a pristine external validation.',
                           'Balanced class weights and label sampling change score interpretation; scores are not calibrated.',
                           'Do not tune further on Friday and present it as a fresh test.',
                           'TrafficLabelling overlaps the same benchmark and is not an external test.',
                           'Exact tree paths explain model decisions, not attacker intent or causal mechanisms.']}
    (output / 'evaluation.json').write_text(json.dumps(report, indent=2))
    lines = ['# Detector upgrade: measured results', '', '| Split | Model | Accuracy | Precision | Recall | F1 | False-positive rate |', '|---|---|---:|---:|---:|---:|---:|']
    for split_name in ['validation', 'same_distribution_test', 'friday_test']:
        for name in ['tree', 'linear_same_training_rows']:
            r = results[split_name][name]
            lines.append(f"| {split_name} | {name} | {r['accuracy']:.3f} | {r['precision']:.3f} | {r['recall']:.3f} | {r['f1']:.3f} | {r['false_positive_rate']:.3f} |")
    lines.extend(['', '## Boundaries', '', *['- ' + x for x in report['cautions']]])
    (output / 'RESULTS.md').write_text('\n'.join(lines) + '\n')
    print(json.dumps({'metadata': metadata, 'results': results}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--data-dir', required=True)
    parser.add_argument('--output', default='instance/model-upgrade')
    args = parser.parse_args()
    train(args.data_dir, args.output)


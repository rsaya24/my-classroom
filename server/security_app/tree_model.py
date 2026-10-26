"""Portable JSON decision tree with exact, inspectable decision-path evidence."""
import numpy as np

from security_app.detection import FIELDS

TREE_FIELDS = FIELDS + ['packets_per_second', 'backward_fraction']


def features(x):
    x = np.asarray(x, dtype=float).reshape(-1, 4)
    total = x[:, 1] + x[:, 2]
    return np.column_stack([x, total / np.maximum(x[:, 0], .001), x[:, 2] / np.maximum(total, 1)]).astype(np.float32)


def export_tree(classifier):
    tree = classifier.tree_
    attack_index = list(classifier.classes_).index(1)
    values = tree.value[:, 0, :]
    return {'left': tree.children_left.tolist(), 'right': tree.children_right.tolist(),
            'feature': tree.feature.tolist(), 'threshold': tree.threshold.tolist(),
            'attack_fraction': (values[:, attack_index] / values.sum(axis=1)).tolist(),
            'samples': tree.n_node_samples.tolist()}


class PortableTree:
    def __init__(self, data):
        self.data = data

    def predict(self, row, threshold=.5):
        values = features(row)[0]
        node, path = 0, []
        contributions = np.zeros(len(TREE_FIELDS))
        while self.data['left'][node] != -1:
            index = self.data['feature'][node]
            boundary = self.data['threshold'][node]
            left = values[index] <= boundary
            child = self.data['left' if left else 'right'][node]
            change = self.data['attack_fraction'][child] - self.data['attack_fraction'][node]
            contributions[index] += change
            path.append({'feature': TREE_FIELDS[index], 'value': float(values[index]),
                         'operator': '<=' if left else '>', 'boundary': boundary,
                         'score_change': change, 'training_samples_in_next_node': self.data['samples'][child]})
            node = child
        score = self.data['attack_fraction'][node]
        return {'score': score, 'threshold': threshold, 'attack_prediction': score >= threshold,
                'explanation_type': 'tree-path', 'path': path,
                'method': 'Exact decision path and changes in node attack fraction; not SHAP and not causal evidence',
                'baseline_score': self.data['attack_fraction'][0], 'leaf_training_samples': self.data['samples'][node],
                'contributions': [{'feature': name, 'value': float(value), 'score_contribution': float(term)}
                                  for name, value, term in zip(TREE_FIELDS, values, contributions)],
                'caveat': 'Leaf attack fraction is uncalibrated and depends on sampling. Derived features are correlated. Collector/domain shift remains unvalidated.'}

    def predict_proba(self, x):
        return np.array([self.predict(row)['score'] for row in x])


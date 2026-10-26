"""On-demand SHAP and LIME; never use test records as explanation background."""
import hashlib
import json
import numpy as np
from security_app.detection import FIELDS, validate_flow


def explain(model, payload):
    import shap
    from lime.lime_tabular import LimeTabularExplainer
    row = validate_flow(payload)
    if model.tree is None:
        raise ValueError('This explanation adapter requires the portable tree')
    artifact = json.loads((model.directory / 'background.json').read_text())
    digest = hashlib.sha256((model.directory / 'tree.json').read_bytes()).hexdigest()
    if artifact['model_sha256'] != digest or artifact['partition'] != 'train':
        raise ValueError('Explanation background does not match the trained model')
    background = np.array(artifact['rows'], dtype=float)
    score = model.tree.predict_proba
    values = shap.Explainer(score, shap.maskers.Independent(background), algorithm='exact')(row[None, :])
    # LIME samples in log space. Recompute derived features and enforce physical bounds.
    def probabilities(z):
        raw = np.expm1(np.clip(z, 0, np.log1p(1e12)))
        raw[:, 1:] = np.rint(raw[:, 1:])
        raw[:, 3] = np.minimum(raw[:, 3], 65535)
        p = score(raw)
        return np.column_stack([1 - p, p])
    local = LimeTabularExplainer(np.log1p(background), feature_names=FIELDS,
        class_names=['normal', 'attack'], random_state=42, discretize_continuous=False)
    result = local.explain_instance(np.log1p(row), probabilities, labels=(1,), num_features=4, num_samples=1000)
    return {'shap': {'baseline': float(values.base_values[0]),
            'contributions': dict(zip(FIELDS, values.values[0].tolist())),
            'reconstructed_score': float(values.base_values[0] + values.values[0].sum())},
        'lime': {'weights': dict(result.as_list(label=1)), 'local_fidelity_r2': float(result.score),
                 'surrogate_score': float(result.local_pred[0])},
        'model_score': float(score(row[None, :])[0]), 'background_rows': len(background),
        'caveat': 'SHAP uses independent masking of four raw features; derived features are recomputed. Correlations can create unrealistic combinations. LIME uses log-space perturbations with rounded counts and bounded ports; weights are local surrogate coefficients, not SHAP values. Low R² means poor local fidelity. Neither method proves intent or causation.'}

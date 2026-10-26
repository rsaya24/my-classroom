from pathlib import Path
import numpy as np
import pytest
from security_app.detection import FlowModel, FIELDS
from security_app.explain import explain

def test_real_shap_lime_reconstruction_and_repeatability():
    model = FlowModel(Path(__file__).parents[1] / 'models/cic-tree')
    payload = dict(zip(FIELDS, [0.1, 2000, 0, 443]))
    first = explain(model, payload)
    second = explain(model, payload)
    assert first['shap']['reconstructed_score'] == pytest.approx(first['model_score'], abs=1e-8)
    assert first['lime'] == second['lime']
    assert np.isfinite(first['lime']['local_fidelity_r2'])
    assert len(first['shap']['contributions']) == 4
    assert first['background_rows'] == 64

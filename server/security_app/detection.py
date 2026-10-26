"""Versioned flow features, exact linear explanations and advisory rules."""
import ipaddress
import json
from pathlib import Path

import numpy as np

from src.model import StandardLogisticRegression

FIELDS = ['duration_seconds', 'forward_packets', 'backward_packets', 'destination_port']
SCHEMA = 'flow-counts-v1'


def validate_flow(data):
    if not isinstance(data, dict):
        raise ValueError('Flow must be a JSON object')
    row = []
    for name in FIELDS:
        value = data.get(name)
        if isinstance(value, bool) or not isinstance(value, (float, int)):
            raise ValueError(f'{name} must be a number')
        if not 0 <= value <= (65535 if name == 'destination_port' else 1e12) or not np.isfinite(value):
            raise ValueError(f'{name} is out of range')
        if name != 'duration_seconds' and int(value) != value:
            raise ValueError(f'{name} must be an integer')
        row.append(value)
    return np.array(row, dtype=float)


def flow_rules(row):
    duration, forward, backward, port = row
    hits = []
    if forward >= 1000 and forward / max(duration, .001) >= 1000:
        hits.append({'rule': 'HIGH_PACKET_RATE', 'evidence': f'{forward:g} forward packets over {duration:g} seconds',
                     'meaning': 'High rate; legitimate bulk traffic can also match.'})
    if forward >= 100 and backward == 0:
        hits.append({'rule': 'UNANSWERED_TRAFFIC', 'evidence': f'{forward:g} forward packets and no backward packets',
                     'meaning': 'One-sided traffic; not proof of a scan or attack.'})
    return hits


class FlowModel:
    def __init__(self, directory):
        directory = Path(directory)
        self.directory = directory
        self.metadata = json.loads((directory / 'metadata.json').read_text())
        if self.metadata['schema'] != SCHEMA:
            raise ValueError('Incompatible model schema')
        self.tree = None
        if self.metadata.get('algorithm') == 'decision-tree-v1':
            from security_app.tree_model import PortableTree
            self.tree = PortableTree(json.loads((directory / 'tree.json').read_text()))
            return
        arrays = np.load(directory / 'model.npz', allow_pickle=False)
        self.model = StandardLogisticRegression()
        for name in ['mean_', 'scale_', 'coef_', 'intercept_']:
            setattr(self.model, name, arrays[name])

    def predict(self, row):
        if self.tree:
            return self.tree.predict(row, self.metadata.get('threshold', .5))
        transformed = np.log1p(row)
        terms = self.model.local_contributions(transformed)
        probability = float(self.model.predict_proba(transformed[None, :])[0])
        return {'score': probability, 'threshold': .5, 'attack_prediction': probability >= .5,
                'method': 'Exact signed contributions to linear log-odds after log1p and training-set standardization; not SHAP',
                'intercept': float(self.model.intercept_),
                'contributions': [{'feature': name, 'value': float(value), 'log_odds_contribution': float(term)}
                                  for name, value, term in zip(FIELDS, row, terms)],
                'caveat': 'Uncalibrated benchmark score, not proof of compromise. Correlated features and collector differences affect interpretation.'}


def location(ip, database=None):
    address = ipaddress.ip_address(ip)
    if not address.is_global:
        return {'status': 'unavailable', 'note': 'Private, loopback or reserved address; no public geolocation.'}
    if not database:
        return {'status': 'unavailable', 'note': 'No local IP-geolocation database configured.'}
    try:
        import geoip2.database
        with geoip2.database.Reader(database) as reader:
            result = reader.city(ip)
            return {'status': 'approximate', 'country': result.country.name, 'city': result.city.name,
                    'note': 'Approximate network location, not the person’s location. VPNs/proxies can conceal the source.'}
    except Exception:
        return {'status': 'unavailable', 'note': 'Address not found or local geolocation lookup unavailable.'}

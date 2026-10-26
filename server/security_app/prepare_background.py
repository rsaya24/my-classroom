"""Rebuild training-only background, verifying the existing partition manifest."""
import argparse
import hashlib
import json
from pathlib import Path
import pandas as pd
from security_app.train import load_data
from security_app.train_upgrade import split
from security_app.detection import FIELDS

def prepare(data_dir, model_dir, manifest):
    frame, _ = load_data(data_dir)
    pool, _ = split(frame.loc[~frame.source.str.startswith('Friday')], .25, 42)
    training, _ = split(pool, .25, 43)
    expected = pd.read_csv(manifest, dtype={'feature_hash': str})
    hashes = pd.util.hash_pandas_object(training[FIELDS], index=False).astype(str)
    if set(hashes) != set(expected.loc[expected.partition.eq('train'), 'feature_hash']):
        raise ValueError('Training partition differs from original manifest')
    directory = Path(model_dir)
    rows = training.sample(n=min(64, len(training)), random_state=42)[FIELDS].to_numpy().tolist()
    artifact = {'partition': 'train', 'sampling': '64 uniform training records, seed 42',
        'model_sha256': hashlib.sha256((directory / 'tree.json').read_bytes()).hexdigest(), 'rows': rows}
    (directory / 'background.json').write_text(json.dumps(artifact, indent=2))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--data-dir', required=True)
    parser.add_argument('--model-dir', required=True)
    parser.add_argument('--manifest', required=True)
    args = parser.parse_args()
    prepare(args.data_dir, args.model_dir, args.manifest)

"""No-hidden-dependency classification metrics and confusion matrix helpers."""
from __future__ import annotations

import numpy as np


def binary_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    tn = int(((y_true == 0) & (y_pred == 0)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "accuracy": (tp + tn) / len(y_true), "precision": precision, "recall": recall,
        "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
        "true_negative": tn, "false_positive": fp, "false_negative": fn, "true_positive": tp,
    }


def format_confusion(metrics: dict) -> str:
    return ("               predicted normal  predicted attack\n"
            f"actual normal  {metrics['true_negative']:16d} {metrics['false_positive']:17d}\n"
            f"actual attack  {metrics['false_negative']:16d} {metrics['true_positive']:17d}")


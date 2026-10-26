"""Small NumPy logistic-regression baseline, deliberately easy to audit."""
from __future__ import annotations

import numpy as np


class StandardLogisticRegression:
    def __init__(self, learning_rate: float = 0.12, epochs: int = 900, l2: float = 0.002):
        self.learning_rate, self.epochs, self.l2 = learning_rate, epochs, l2

    def fit(self, x: np.ndarray, y: np.ndarray) -> "StandardLogisticRegression":
        self.mean_ = x.mean(axis=0)
        self.scale_ = x.std(axis=0)
        self.scale_[self.scale_ == 0] = 1.0
        z = (x - self.mean_) / self.scale_
        self.coef_ = np.zeros(z.shape[1])
        self.intercept_ = 0.0
        for _ in range(self.epochs):
            scores = np.clip(z @ self.coef_ + self.intercept_, -35, 35)
            p = 1 / (1 + np.exp(-scores))
            error = p - y
            self.coef_ -= self.learning_rate * ((z.T @ error) / len(z) + self.l2 * self.coef_)
            self.intercept_ -= self.learning_rate * error.mean()
        return self

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        z = (x - self.mean_) / self.scale_
        scores = np.clip(z @ self.coef_ + self.intercept_, -35, 35)
        return 1 / (1 + np.exp(-scores))

    def predict(self, x: np.ndarray, threshold: float = 0.5) -> np.ndarray:
        return (self.predict_proba(x) >= threshold).astype(int)

    def local_contributions(self, row: np.ndarray) -> np.ndarray:
        """Exact signed feature terms for this linear model's log-odds, not SHAP values."""
        return ((row - self.mean_) / self.scale_) * self.coef_


"""2단계: 라벨 없이 학습하는 이상 탐지(Isolation Forest)."""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from .features import FEATURES


class AnomalyModel:
    """점수를 학습 구간 점수 분포의 백분위(0~1)로 바꿔 돌려준다.

    0.97이면 '학습 기간 로그인의 97%보다 이상하다'는 뜻이라 임계값을 정하기 쉽다.
    """

    def __init__(self, seed: int = 7):
        self.forest = IsolationForest(n_estimators=200, random_state=seed)
        self._ref: np.ndarray | None = None

    def fit(self, X: pd.DataFrame) -> "AnomalyModel":
        self.forest.fit(X[FEATURES])
        self._ref = np.sort(-self.forest.score_samples(X[FEATURES]))
        return self

    def score(self, X: pd.DataFrame) -> np.ndarray:
        raw = -self.forest.score_samples(X[FEATURES])
        return np.searchsorted(self._ref, raw, side="right") / len(self._ref)

"""3단계: 위험도에 따라 통과·추가 인증·차단으로 나눈다."""
from __future__ import annotations

import numpy as np
import pandas as pd

from .features import IMPOSSIBLE_KMH

STEP_UP = 0.97   # 추가 인증(OTP, 이메일 확인)
BLOCK = 0.995    # 차단 + 사용자 알림
SENSITIVE_ACTIONS = {"password_change", "points_redeem", "contact_change"}
SENSITIVE_STEP_UP = 0.85  # 로그인은 통과했어도 민감 행동 직전에 다시 확인


def decide(df: pd.DataFrame) -> pd.DataFrame:
    """rule_score, model_score, speed_kmh, action 열이 있는 df에 판정을 붙인다."""
    risk = np.maximum(df["rule_score"], df["model_score"])
    impossible = df["speed_kmh"] > IMPOSSIBLE_KMH
    risk = np.where(impossible, np.maximum(risk, STEP_UP), risk)
    # 모델 점수만으로는 차단하지 않는다. 규칙 근거나 불가능한 이동이 같이 있어야 차단.
    hard_evidence = (df["rule_score"] > 0) | impossible
    decision = np.select([(risk >= BLOCK) & hard_evidence, risk >= STEP_UP],
                         ["block", "step_up"], "allow")
    # 로그인 직후 민감 행동은 문턱을 낮춰 한 번 더 막는다.
    escalate = ((decision == "allow") & df["action"].isin(SENSITIVE_ACTIONS)
                & (risk >= SENSITIVE_STEP_UP))
    decision = np.where(escalate, "step_up_action", decision)
    return df.assign(risk=risk, decision=decision)

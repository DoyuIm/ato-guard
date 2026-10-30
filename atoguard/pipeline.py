"""생성 → 규칙 → 특징 → 모델 → 판정 → 섀도 모드 평가까지 한 번에 돌린다.

    python -m atoguard.pipeline
"""
from __future__ import annotations

from pathlib import Path

import pandas as pd

from . import risk as R
from .features import build_features
from .generate import DAYS, START, generate
from .model import AnomalyModel
from .rules import apply_rules
from .summarize import llm_summary

SPLIT = START + pd.Timedelta(days=DAYS // 2)  # 앞 30일 학습, 뒤 30일 섀도 모드


def run(n_users: int = 500, seed: int = 7) -> pd.DataFrame:
    df, bad_ips = generate(n_users, seed)
    df = build_features(apply_rules(df, bad_ips))
    train = df[(df.ts < SPLIT) & df.success]  # 라벨은 쓰지 않는다(비지도)
    df["model_score"] = AnomalyModel(seed).fit(train).score(df)
    return R.decide(df)


def _caught(d: pd.Series) -> float:
    return float((d != "allow").mean()) if len(d) else float("nan")


def evaluate(df: pd.DataFrame) -> dict:
    """뒤 30일만 본다. 공격은 '로그인에 성공한 시도'를 잡았는지가 핵심 지표다."""
    t = df[df.ts >= SPLIT]
    ok = t[t.success]
    normal, attack = ok[ok.label == 0], ok[ok.label == 1]
    res = {
        "normal_logins": len(normal),
        "normal_step_up_rate": float((normal.decision != "allow").mean()),
        "normal_block_rate": float((normal.decision == "block").mean()),
        "attack_logins": len(attack),
        "attack_caught_rate": _caught(attack.decision),
        "stuffing_attempts": int((t.attack_type == "stuffing").sum()),
        "stuffing_blocked_rate": float((t[t.attack_type == "stuffing"].decision == "block").mean()),
    }
    for kind in ("stuffing", "ato"):
        res[f"{kind}_success_caught"] = _caught(attack[attack.attack_type == kind].decision)
    # 규칙만 / 모델만 썼을 때와 비교(겹쳐 쓰는 효과 확인)
    for name, col in (("rules_only", "rule_score"), ("model_only", "model_score")):
        res[f"{name}_attack_caught"] = float((attack[col] >= R.STEP_UP).mean())
        res[f"{name}_normal_step_up"] = float((normal[col] >= R.STEP_UP).mean())
    return res


def write_report(df: pd.DataFrame, res: dict, path: Path) -> None:
    pct = lambda k: f"{res[k]:.1%}"
    t = df[(df.ts >= SPLIT) & df.success & (df.decision != "allow")]
    samples = pd.concat([t[t.label == 1].head(4), t[t.label == 0].head(2)])
    lines = [
        "# 섀도 모드 리포트 (합성 데이터, 뒤 30일)", "",
        "| 지표 | 값 |", "|---|---|",
        f"| 정상 로그인 수 | {res['normal_logins']:,} |",
        f"| 정상 로그인 추가 인증 비율(오탐) | {pct('normal_step_up_rate')} |",
        f"| 정상 로그인 차단 비율 | {pct('normal_block_rate')} |",
        f"| 공격자 로그인 성공 건수 | {res['attack_logins']} |",
        f"| 그중 추가 인증·차단으로 막은 비율(탐지율) | {pct('attack_caught_rate')} |",
        f"| └ 스터핑으로 뚫린 계정 | {pct('stuffing_success_caught')} |",
        f"| └ 표적 탈취(ATO) | {pct('ato_success_caught')} |",
        f"| 스터핑 시도 수 / 차단 비율 | {res['stuffing_attempts']:,} / {pct('stuffing_blocked_rate')} |",
        "", "## 규칙과 모델을 겹쳐 쓴 효과", "",
        "| 방식 | 탐지율 | 오탐 |", "|---|---|---|",
        f"| 규칙만 | {pct('rules_only_attack_caught')} | {pct('rules_only_normal_step_up')} |",
        f"| 모델만 | {pct('model_only_attack_caught')} | {pct('model_only_normal_step_up')} |",
        f"| 규칙+모델+위험도 대응 | {pct('attack_caught_rate')} | {pct('normal_step_up_rate')} |",
        "", "## 운영자용 요약 예시", "",
        *[f"- {'공격' if r.label else '정상'} · {llm_summary(r)}" for r in samples.itertuples()],
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    df = run()
    res = evaluate(df)
    for k, v in res.items():
        print(f"{k:28s} {v:.4f}" if isinstance(v, float) else f"{k:28s} {v}")
    write_report(df, res, Path("reports/shadow_report.md"))
    print("wrote reports/shadow_report.md")

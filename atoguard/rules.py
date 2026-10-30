"""1단계: 규칙 기반 탐지. 학습 없이 바로 적용할 수 있는 것들."""
from __future__ import annotations

from collections import defaultdict, deque

import pandas as pd

WINDOW = pd.Timedelta(minutes=10)
MAX_FAILS_PER_IP = 10        # 10분 안에 같은 IP에서 실패 10회
MAX_ACCOUNTS_PER_IP = 5      # 10분 안에 같은 IP가 계정 5개 이상 시도


def apply_rules(df: pd.DataFrame, bad_ips: set[str]) -> pd.DataFrame:
    """시간순 df에 rule_score(0~1)와 rule_hits(문자열)를 붙여 돌려준다.

    각 이벤트는 그 시점까지 본 로그만으로 판정한다(미래 정보 누수 없음).
    """
    fails: dict[str, deque] = defaultdict(deque)
    accounts: dict[str, deque] = defaultdict(deque)
    scores, hits = [], []
    for ts, ip, uid, ok, ip_type in df[["ts", "ip", "user_id", "success", "ip_type"]].itertuples(index=False):
        for q in (fails[ip], accounts[ip]):
            while q and ts - q[0][0] > WINDOW:
                q.popleft()
        accounts[ip].append((ts, uid))
        h = []
        if ip in bad_ips:
            h.append("known_bad_ip")
        if len(fails[ip]) >= MAX_FAILS_PER_IP:
            h.append("ip_fail_burst")
        if len({u for _, u in accounts[ip]}) >= MAX_ACCOUNTS_PER_IP:
            h.append("ip_many_accounts")
        if ip_type == "datacenter":
            h.append("datacenter_ip")
        if not ok:
            fails[ip].append((ts, uid))
        score = (1.0 if {"known_bad_ip", "ip_fail_burst", "ip_many_accounts"} & set(h)
                 else 0.7 if h else 0.0)
        scores.append(score)
        hits.append(",".join(h))
    return df.assign(rule_score=scores, rule_hits=hits)

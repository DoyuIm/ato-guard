"""합성 로그인 로그 생성기.

정상 사용자 행동에 크리덴셜 스터핑과 계정 탈취(ATO) 공격을 섞어서
라벨이 붙은 로그를 만든다. 실서비스 로그가 없는 상태에서 파이프라인을
검증하기 위한 용도다.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

START = pd.Timestamp("2026-08-01")
DAYS = 60

KR_CITIES = {
    "Seoul": (37.57, 126.98),
    "Busan": (35.18, 129.08),
    "Daegu": (35.87, 128.60),
    "Incheon": (37.46, 126.70),
    "Gwangju": (35.16, 126.85),
    "Daejeon": (36.35, 127.38),
}
FOREIGN = {
    ("US", "Los Angeles"): (34.05, -118.24),
    ("RU", "Moscow"): (55.75, 37.62),
    ("VN", "Hanoi"): (21.03, 105.85),
    ("NL", "Amsterdam"): (52.37, 4.90),
    ("BR", "Sao Paulo"): (-23.55, -46.63),
}
SENSITIVE = ["password_change", "points_redeem", "contact_change"]


def _ip(rng: np.random.Generator, prefix: str) -> str:
    return f"{prefix}.{rng.integers(0, 256)}.{rng.integers(0, 256)}.{rng.integers(1, 255)}"


def _row(ts, user, ip, ip_type, country, city, latlon, device, ua, success,
         action="none", label=0, attack="normal"):
    return dict(ts=ts, user_id=user, ip=ip, ip_type=ip_type, country=country,
                city=city, lat=latlon[0], lon=latlon[1], device_id=device, ua=ua,
                success=success, action=action, label=label, attack_type=attack)


def _normal_users(rng, n_users):
    rows, users = [], []
    for u in range(n_users):
        uid = f"u{u:04d}"
        city = rng.choice(list(KR_CITIES))
        ua = "mobile" if rng.random() < 0.85 else "pc"
        devices = [f"d{u:04d}_{k}" for k in range(rng.integers(1, 3))]
        ips = [_ip(rng, "211" if ua == "pc" else "223") for _ in range(rng.integers(2, 4))]
        center, rate = rng.uniform(9, 22), rng.uniform(0.5, 2.5)
        users.append(uid)
        for day in range(DAYS):
            for _ in range(rng.poisson(rate)):
                hour = np.clip(rng.normal(center, 3), 0, 23.99)
                ts = START + pd.Timedelta(days=day, hours=float(hour))
                c, ip, dev, this_ua = city, rng.choice(ips), rng.choice(devices), ua
                if rng.random() < 0.03:  # 국내 출장·여행
                    c = rng.choice([k for k in KR_CITIES if k != city])
                    ip = _ip(rng, "223")
                if rng.random() < 0.015:  # 기기 교체·PC방
                    dev, this_ua = f"d{u:04d}_new{day}", rng.choice(["mobile", "pc"])
                    devices.append(dev)
                ip_type = "mobile" if ip.startswith("223") else "residential"
                base = (ip, ip_type, "KR", c, KR_CITIES[c], dev, this_ua)
                if rng.random() < 0.04:  # 비밀번호 오타
                    rows.append(_row(ts - pd.Timedelta(seconds=20), uid, *base, False))
                r = rng.random()
                action = ("points_redeem" if r < 0.03 else
                          "password_change" if r < 0.033 else
                          "contact_change" if r < 0.035 else "none")
                rows.append(_row(ts, uid, *base, True, action))
    return rows, users


def _stuffing(rng, users, bad_ips):
    """데이터센터 IP 여러 개로 유출 계정을 짧은 시간에 대량 대입."""
    rows = []
    for _ in range(8):
        country, city = list(FOREIGN)[rng.integers(len(FOREIGN))]
        latlon = FOREIGN[(country, city)]
        ips = [_ip(rng, "45") for _ in range(rng.integers(3, 11))]
        bad_ips.update(ip for ip in ips if rng.random() < 0.5)
        t0 = START + pd.Timedelta(days=float(rng.uniform(1, DAYS - 1)))
        dur = rng.uniform(20, 60)
        for _ in range(rng.integers(200, 800)):
            ts = t0 + pd.Timedelta(minutes=float(rng.uniform(0, dur)))
            real = rng.random() < 0.6
            uid = rng.choice(users) if real else f"ghost_{rng.integers(1e6)}"
            ok = real and rng.random() < 0.015
            action = rng.choice(SENSITIVE) if ok and rng.random() < 0.7 else "none"
            rows.append(_row(ts, uid, rng.choice(ips), "datacenter", country, city,
                             latlon, f"bot_{rng.integers(50)}", "pc", ok, action,
                             1, "stuffing"))
    return rows


def _targeted_ato(rng, users, normal_rows, n=40):
    """한 계정을 노린 탈취 로그인.

    25%는 어려운 케이스다. 피해자와 같은 도시의 국내 IP를 쓰고, 절반은 기기 지문까지
    위조(안티디텍트 브라우저)해서 평소 기기로 보이게 한다.
    """
    by_user: dict[str, list[dict]] = {}
    for r in normal_rows:
        if r["success"]:
            by_user.setdefault(r["user_id"], []).append(r)
    rows = []
    for i in range(n):
        uid = rng.choice(users)
        day = rng.uniform(5, DAYS - 1)
        if rng.random() < 0.25:
            ref = by_user[uid][rng.integers(len(by_user[uid]))]
            dev = ref["device_id"] if rng.random() < 0.5 else f"atk_{i}"
            ts = START + pd.Timedelta(days=float(int(day)), hours=float(rng.uniform(10, 22)))
            base = (_ip(rng, "223"), "mobile", "KR", ref["city"],
                    KR_CITIES[ref["city"]], dev, ref["ua"])
        else:
            country, city = list(FOREIGN)[rng.integers(len(FOREIGN))]
            ts = START + pd.Timedelta(days=float(int(day)), hours=float(rng.uniform(1, 5)))
            ip_type = "datacenter" if rng.random() < 0.4 else "residential"
            base = (_ip(rng, "45" if ip_type == "datacenter" else "88"), ip_type,
                    country, city, FOREIGN[(country, city)], f"atk_{i}", "pc")
        for k in range(rng.integers(0, 3)):
            rows.append(_row(ts - pd.Timedelta(minutes=k + 1), uid, *base, False,
                             label=1, attack="ato"))
        action = rng.choice(SENSITIVE) if rng.random() < 0.8 else "none"
        rows.append(_row(ts, uid, *base, True, action, 1, "ato"))
    return rows


def generate(n_users: int = 500, seed: int = 7) -> tuple[pd.DataFrame, set[str]]:
    """(로그 DataFrame, 알려진 악성 IP 목록)을 돌려준다."""
    rng = np.random.default_rng(seed)
    rows, users = _normal_users(rng, n_users)
    bad_ips: set[str] = {_ip(rng, "45") for _ in range(30)}
    rows += _stuffing(rng, users, bad_ips)
    rows += _targeted_ato(rng, users, list(rows))
    df = pd.DataFrame(rows).sort_values("ts", kind="stable").reset_index(drop=True)
    return df, bad_ips

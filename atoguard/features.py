"""2단계 입력: 사용자별 '평소 패턴' 대비 이번 로그인이 얼마나 벗어났는지."""
from __future__ import annotations

import math
from collections import Counter, defaultdict, deque

import pandas as pd

FEATURES = ["new_device", "new_country", "new_city", "hour_dev", "speed_kmh_log",
            "is_datacenter", "ua_mismatch", "acct_fails_1h"]
IMPOSSIBLE_KMH = 900  # 여객기보다 빠른 이동


def _km(a, b):
    lat1, lon1, lat2, lon2 = map(math.radians, (*a, *b))
    h = (math.sin((lat2 - lat1) / 2) ** 2
         + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2)
    return 12742 * math.asin(math.sqrt(h))


def _hour_gap(h, hours):
    """평소 접속 시각들과의 원형 거리(시간). 23시와 1시는 2시간 차이."""
    mean = math.atan2(sum(math.sin(x / 24 * 2 * math.pi) for x in hours),
                      sum(math.cos(x / 24 * 2 * math.pi) for x in hours))
    d = abs(h - (mean / (2 * math.pi) * 24) % 24)
    return min(d, 24 - d)


class _History:
    def __init__(self):
        self.devices, self.countries, self.cities = set(), set(), set()
        self.hours: deque = deque(maxlen=50)
        self.uas: Counter = Counter()
        self.last = None  # (ts, (lat, lon))
        self.fails: deque = deque()


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    """시간순 df에 FEATURES와 speed_kmh 열을 붙인다. 과거 로그인만 참고한다.

    기록은 성공한 로그인으로만 쌓는다. 실패 시도는 계정 실패 횟수에만 반영한다.
    """
    hist: dict[str, _History] = defaultdict(_History)
    out = []
    for r in df.itertuples(index=False):
        h = hist[r.user_id]
        while h.fails and r.ts - h.fails[0] > pd.Timedelta(hours=1):
            h.fails.popleft()
        hour = r.ts.hour + r.ts.minute / 60
        has_hist = bool(h.hours)
        speed = 0.0
        if h.last is not None:
            hrs = max((r.ts - h.last[0]).total_seconds() / 3600, 1 / 60)
            speed = _km(h.last[1], (r.lat, r.lon)) / hrs
        out.append(dict(
            new_device=int(r.device_id not in h.devices),
            new_country=int(has_hist and r.country not in h.countries),
            new_city=int(has_hist and r.city not in h.cities),
            hour_dev=_hour_gap(hour, h.hours) if has_hist else 0.0,
            speed_kmh=speed,
            speed_kmh_log=math.log1p(speed),
            is_datacenter=int(r.ip_type == "datacenter"),
            ua_mismatch=int(has_hist and r.ua != h.uas.most_common(1)[0][0]),
            acct_fails_1h=len(h.fails),
        ))
        if r.success:
            h.devices.add(r.device_id)
            h.countries.add(r.country)
            h.cities.add(r.city)
            h.hours.append(hour)
            h.uas[r.ua] += 1
            h.last = (r.ts, (r.lat, r.lon))
        else:
            h.fails.append(r.ts)
    return pd.concat([df, pd.DataFrame(out, index=df.index)], axis=1)

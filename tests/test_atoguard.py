import pandas as pd

from atoguard.features import build_features
from atoguard.pipeline import evaluate, run
from atoguard.risk import decide
from atoguard.rules import apply_rules
from atoguard.summarize import template_summary

T0 = pd.Timestamp("2026-08-01 09:00")


def ev(minutes, user="u1", ip="1.1.1.1", city="Seoul", latlon=(37.57, 126.98),
       country="KR", device="d1", ok=True, ip_type="mobile", action="none"):
    return dict(ts=T0 + pd.Timedelta(minutes=minutes), user_id=user, ip=ip,
                ip_type=ip_type, country=country, city=city, lat=latlon[0],
                lon=latlon[1], device_id=device, ua="mobile", success=ok,
                action=action, label=0, attack_type="normal")


def test_impossible_travel_and_new_country():
    df = pd.DataFrame([ev(0), ev(10, country="US", city="Los Angeles",
                                 latlon=(34.05, -118.24), device="x")])
    f = build_features(df)
    assert f.speed_kmh.iloc[1] > 900
    assert f.new_country.iloc[1] == 1 and f.new_device.iloc[1] == 1
    assert f.new_country.iloc[0] == 0  # 기록이 없으면 '새 국가'로 치지 않는다


def test_failed_attempts_do_not_become_history():
    df = pd.DataFrame([ev(0, device="atk", ok=False), ev(1, device="atk")])
    f = build_features(df)
    assert f.new_device.iloc[1] == 1
    assert f.acct_fails_1h.iloc[1] == 1


def test_ip_burst_rule_uses_only_past_events():
    rows = [ev(i * 0.1, user=f"u{i}", ip="9.9.9.9", ok=False) for i in range(12)]
    r = apply_rules(pd.DataFrame(rows), bad_ips=set())
    assert r.rule_score.iloc[0] == 0
    assert "ip_many_accounts" in r.rule_hits.iloc[5]
    assert "ip_fail_burst" in r.rule_hits.iloc[10]


def test_model_alone_never_blocks():
    df = pd.DataFrame(dict(rule_score=[0.0, 1.0], model_score=[1.0, 0.0],
                           speed_kmh=[0.0, 0.0], action=["none", "none"]))
    assert list(decide(df).decision) == ["step_up", "block"]


def test_sensitive_action_escalates():
    df = pd.DataFrame(dict(rule_score=[0.0], model_score=[0.9], speed_kmh=[0.0],
                           action=["password_change"]))
    assert decide(df).decision.iloc[0] == "step_up_action"


def test_end_to_end_small():
    df = run(n_users=120, seed=3)
    res = evaluate(df)
    assert res["attack_caught_rate"] > 0.7
    assert res["normal_step_up_rate"] < 0.06
    row = df[df.decision != "allow"].iloc[0]
    assert row.user_id in template_summary(row)

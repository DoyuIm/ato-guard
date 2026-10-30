"""운영자용 요약. GEMINI_API_KEY가 있으면 LLM으로 다듬고, 없으면 템플릿만 쓴다."""
from __future__ import annotations

import json
import os
import urllib.request

ACTION_KO = {"password_change": "비밀번호 변경", "points_redeem": "포인트 사용",
             "contact_change": "연락처 변경"}
RULE_KO = {"known_bad_ip": "악성 IP 목록에 있음", "ip_fail_burst": "같은 IP에서 실패 급증",
           "ip_many_accounts": "같은 IP로 여러 계정 시도", "datacenter_ip": "데이터센터 IP"}


def evidence(row) -> list[str]:
    """판정 근거를 사람이 읽을 수 있는 문장 조각으로 모은다."""
    e = [RULE_KO[h] for h in str(row.rule_hits).split(",") if h in RULE_KO]
    if row.new_country:
        e.append(f"처음 보는 국가({row.country})")
    elif row.new_city:
        e.append(f"처음 보는 지역({row.city})")
    if row.new_device:
        e.append(f"처음 보는 기기({row.ua})")
    if row.ua_mismatch:
        e.append("평소와 다른 기기 종류")
    if row.hour_dev >= 6:
        e.append(f"평소와 {row.hour_dev:.0f}시간 어긋난 시각({row.ts:%H:%M})")
    if row.speed_kmh > 900:
        e.append(f"직전 로그인 대비 시속 {row.speed_kmh:,.0f}km 이동(물리적으로 불가능)")
    if row.acct_fails_1h:
        e.append(f"최근 1시간 실패 {row.acct_fails_1h}회")
    if row.action in ACTION_KO:
        e.append(f"로그인 직후 {ACTION_KO[row.action]} 시도")
    return e


def template_summary(row) -> str:
    parts = evidence(row) or ["뚜렷한 단일 근거 없이 여러 특징이 조금씩 벗어남"]
    return (f"[{row.decision}] 계정 {row.user_id}, 위험도 {row.risk:.3f}: "
            + ", ".join(parts) + ".")


def llm_summary(row, model: str | None = None) -> str:
    """Gemini로 한두 문장 요약을 만든다. 키가 없거나 실패하면 템플릿으로 대신한다."""
    key = os.environ.get("GEMINI_API_KEY")
    base = template_summary(row)
    if not key:
        return base
    model = model or os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
    prompt = ("보안 운영자에게 보여줄 로그인 이상 징후 요약을 한국어 한두 문장으로 써줘. "
              "근거에 없는 내용은 추가하지 마.\n근거: " + base)
    req = urllib.request.Request(
        f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        data=json.dumps({"contents": [{"parts": [{"text": prompt}]}]}).encode(),
        headers={"Content-Type": "application/json", "x-goog-api-key": key})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            body = json.load(resp)
        return body["candidates"][0]["content"]["parts"][0]["text"].strip()
    except Exception:
        return base

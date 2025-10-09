# /core/vt_client.py
import os
import time
import base64
import requests
from typing import Optional, Dict
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
VT_BASE = "https://www.virustotal.com/api/v3"

HEADERS = {"x-apikey": VT_API_KEY} if VT_API_KEY else {}

def _url_id(url: str) -> str:
    # VT는 URL-safe base64 (padding 제거) id를 사용
    enc = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii")
    return enc.strip("=")

def vt_fetch_url_report(url: str, submit_if_absent: bool = True, max_wait_sec: int = 6) -> Dict:
    """
    URL에 대한 VT 요약 리포트를 반환.
    - 먼저 GET /urls/{id}로 조회
    - 없으면 (선택) POST /urls 로 제출 후 최대 max_wait_sec 만큼 폴링
    - 항상 가벼운 요약 딕셔너리를 반환 (API 응답 원본 X)
    """
    if not VT_API_KEY:
        return {"status": "disabled", "reason": "VT_API_KEY not set"}

    # 1) 캐시/기존 리포트 조회
    url_id = _url_id(url)
    url_get = f"{VT_BASE}/urls/{url_id}"
    r = requests.get(url_get, headers=HEADERS, timeout=15)

    if r.status_code == 200:
        data = r.json().get("data", {})
        return _summarize_url_data(data)

    if r.status_code not in (404, 400):
        # 그 외 에러는 그대로 전달
        return {"status": "error", "http_status": r.status_code, "detail": r.text[:500]}

    # 2) 없으면 제출 (옵션)
    if not submit_if_absent:
        return {"status": "not_found"}

    submit = requests.post(f"{VT_BASE}/urls", headers=HEADERS, data={"url": url}, timeout=15)
    if submit.status_code not in (200, 201):
        return {"status": "submit_failed", "http_status": submit.status_code, "detail": submit.text[:500]}

    # 분석 id로 폴링
    analysis_id = submit.json().get("data", {}).get("id")
    if not analysis_id:
        return {"status": "submit_failed", "detail": "no analysis id returned"}

    # 짧게 폴링 (최대 max_wait_sec)
    waited = 0
    while waited < max_wait_sec:
        time.sleep(1)
        waited += 1
        g = requests.get(url_get, headers=HEADERS, timeout=15)
        if g.status_code == 200:
            data = g.json().get("data", {})
            return _summarize_url_data(data)
    # 폴링 타임아웃
    return {"status": "queued"}

def _summarize_url_data(data: Dict) -> Dict:
    attrs = data.get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    votes = attrs.get("total_votes", {})
    return {
        "status": "ok",
        "url": attrs.get("last_final_url") or attrs.get("url"),
        "title": attrs.get("title"),
        "reputation": attrs.get("reputation"),
        "categories": attrs.get("categories", {}),
        "last_http_response_code": attrs.get("last_http_response_code"),
        "last_analysis_stats": stats,
        "total_votes": votes,
        # 아주 큰 본문은 안 내보내고 핵심만 요약
        "summary_flag": _label_from_stats(stats)
    }

def _label_from_stats(stats: Dict) -> str:
    mal = int(stats.get("malicious", 0))
    susp = int(stats.get("suspicious", 0))
    if mal > 0:
        return "malicious"
    if susp > 0:
        return "suspicious"
    return "clean_or_unknown"
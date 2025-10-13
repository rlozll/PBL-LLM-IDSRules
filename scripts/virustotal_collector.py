#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VirusTotal v3 연동 모듈
- 모듈형 run(limit=...) 제공 → orchestrator에서 호출
- CLI와 병행 가능: python -m scripts.collectors.virustotal_collector --url ...
- URL: 캐시 없으면 스캔 등록 → 분석 폴링 → 최종 리포트 저장
- Domain/IP/Hash: 즉시 조회
- RSS 파서 산출물(data/rss_parsed/*.json)에서 URL 자동 수집 + 중복 방지
"""

import os
import json
import time
import logging
import base64
import glob
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional
import argparse
import requests

# ─────────────────────────────────────────────────────
# 환경/경로
# ─────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parents[2]  # .../PBL-LLM-IDSRules
OUT_DIR = BASE_DIR / "data" / "virustotal"
RSS_DIR = BASE_DIR / "data" / "rss_parsed"
STATE_PATH = OUT_DIR / ".state.json"

OUT_DIR.mkdir(parents=True, exist_ok=True)

# .env 로드 (없으면 넘어감)
try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=BASE_DIR / ".env")
except Exception:
    pass

VT_API_KEY = os.getenv("VT_API_KEY")
HEADERS = {"x-apikey": VT_API_KEY} if VT_API_KEY else {}

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("vt")

# 퍼블릭 키 기준 보수적 안전슬립:
# - 제출(POST) 후: 16초 슬립
# - 캐시 히트(GET 200): 1초 슬립
SLEEP_AFTER_POST = float(os.getenv("VT_SLEEP_AFTER_POST", "16"))
SLEEP_AFTER_GET  = float(os.getenv("VT_SLEEP_AFTER_GET",  "1"))

# ─────────────────────────────────────────────────────
# 유틸
# ─────────────────────────────────────────────────────
def b64url_no_pad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def save_json(name: str, data: dict) -> str:
    safe = name.replace("/", "_").replace(":", "_")
    path = OUT_DIR / f"{safe}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    log.info(f"✅ 저장: {path}")
    return str(path)

def load_state() -> Dict[str, dict]:
    if STATE_PATH.exists():
        try:
            return json.loads(STATE_PATH.read_text("utf-8"))
        except Exception:
            return {}
    return {}

def save_state(state: Dict[str, dict]) -> None:
    STATE_PATH.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")

# ─────────────────────────────────────────────────────
# VT REST
# ─────────────────────────────────────────────────────
def vt_get_url_report(url: str) -> dict:
    """URL 리포트 가져오기 (캐시 없으면 스캔 후 폴링)"""
    if not VT_API_KEY:
        raise RuntimeError("VT_API_KEY가 설정되지 않음 (.env 또는 환경변수 필요)")

    url_id = b64url_no_pad(url.encode("utf-8"))
    get_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    r = requests.get(get_url, headers=HEADERS, timeout=30)
    if r.status_code == 200:
        # 캐시 히트
        time.sleep(SLEEP_AFTER_GET)
        return r.json()

    if r.status_code != 404:
        # 401/403/429 등
        log.error(f"❌ URL 조회 실패: status={r.status_code} body={r.text}")
        r.raise_for_status()

    # 404 → 캐시 없음 → 스캔 등록
    log.info("ℹ️ 캐시 없음 → URL 스캔 등록 (POST /urls)")
    analysis_id, submit_resp = vt_submit_url(url)
    # 제출결과도 남겨두고 싶으면 저장
    save_json(f"submit__{url_id}", submit_resp)

    # 분석 완료까지 폴링
    vt_poll_analysis(analysis_id)

    # 완료 후 최종 리포트
    r2 = requests.get(get_url, headers=HEADERS, timeout=30)
    if r2.status_code != 200:
        log.error(f"❌ 최종 리포트 조회 실패: status={r2.status_code} body={r2.text}")
        r2.raise_for_status()
    time.sleep(SLEEP_AFTER_GET)
    return r2.json()

def vt_submit_url(url: str):
    r = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=HEADERS,
        data={"url": url},
        timeout=30,
    )
    if r.status_code not in (200, 202):
        log.error(f"❌ URL 제출 실패: status={r.status_code} body={r.text}")
        r.raise_for_status()
    data = r.json()
    analysis_id = data.get("data", {}).get("id")
    if not analysis_id:
        raise RuntimeError(f"분석 ID 획득 실패: {data}")
    log.info(f"📝 분석 등록: analysis_id={analysis_id}")
    # 제출 후 레이트 가드
    time.sleep(SLEEP_AFTER_POST)
    return analysis_id, data

def vt_poll_analysis(analysis_id: str, timeout_sec: int = 120, interval_sec: int = 3) -> None:
    """/analyses/{id} 폴링하여 status == completed 대기"""
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        r = requests.get(url, headers=HEADERS, timeout=30)
        if r.status_code != 200:
            log.warning(f"분석 상태 조회 실패: status={r.status_code} body={r.text}")
        else:
            j = r.json()
            status = j.get("data", {}).get("attributes", {}).get("status")
            log.info(f"⏳ 분석 상태: {status}")
            if status == "completed":
                return
        time.sleep(interval_sec)
    raise TimeoutError("분석 완료 대기 타임아웃")

def vt_get_domain_report(domain: str) -> dict:
    if not VT_API_KEY:
        raise RuntimeError("VT_API_KEY가 설정되지 않음")
    r = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=HEADERS, timeout=30)
    if r.status_code != 200:
        log.error(f"❌ 도메인 조회 실패: status={r.status_code} body={r.text}")
        r.raise_for_status()
    time.sleep(SLEEP_AFTER_GET)
    return r.json()

def vt_get_ip_report(ip: str) -> dict:
    if not VT_API_KEY:
        raise RuntimeError("VT_API_KEY가 설정되지 않음")
    r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=HEADERS, timeout=30)
    if r.status_code != 200:
        log.error(f"❌ IP 조회 실패: status={r.status_code} body={r.text}")
        r.raise_for_status()
    time.sleep(SLEEP_AFTER_GET)
    return r.json()

def vt_get_file_report(sha256: str) -> dict:
    if not VT_API_KEY:
        raise RuntimeError("VT_API_KEY가 설정되지 않음")
    r = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256}", headers=HEADERS, timeout=30)
    if r.status_code != 200:
        log.error(f"❌ 파일 해시 조회 실패: status={r.status_code} body={r.text}")
        r.raise_for_status()
    time.sleep(SLEEP_AFTER_GET)
    return r.json()

# ─────────────────────────────────────────────────────
# RSS URL 공급원 + 중복 방지
# ─────────────────────────────────────────────────────
def iter_urls_from_rss(max_files: int = 10) -> Iterator[str]:
    """
    최신 RSS 파싱 파일들에서 기사 URL 뽑아냄.
    파일 포맷 가정: 각 JSON에 entries:[{link: "..."}] 또는 items:[{link: "..."}]
    """
    paths = sorted(glob.glob(str(RSS_DIR / "*.json")), key=os.path.getmtime, reverse=True)[:max_files]
    for p in paths:
        try:
            data = json.loads(Path(p).read_text("utf-8"))
        except Exception:
            continue
        entries = data.get("entries") or data.get("items") or []
        for it in entries:
            url = it.get("link") or it.get("url")
            if url and url.startswith(("http://", "https://")):
                yield url

def choose_targets(limit: int) -> List[str]:
    """
    RSS에서 최신 URL 뽑고, 이미 처리한 URL은 제외하여 상위 limit 반환
    """
    state = load_state()
    seen = state.get("seen_urls", {})
    result: List[str] = []
    for url in iter_urls_from_rss(max_files=15):
        k = b64url_no_pad(url.encode())
        if k in seen:
            continue
        result.append(url)
        if len(result) >= limit:
            break
    return result

def mark_seen(urls: Iterable[str]) -> None:
    state = load_state()
    seen = state.get("seen_urls", {})
    ts = time.time()
    for url in urls:
        k = b64url_no_pad(url.encode())
        seen[k] = {"url": url, "ts": ts}
    state["seen_urls"] = seen
    save_state(state)

# ─────────────────────────────────────────────────────
# 모듈 엔트리포인트: orchestrator용
# ─────────────────────────────────────────────────────
def run(limit: int = 4) -> None:
    """
    orchestrator가 호출하는 진입점.
    - limit 개의 새 URL을 RSS에서 뽑아서 VT 조회/스캔
    - 결과 JSON 저장 (data/virustotal/)
    - 중복 방지 상태 갱신
    """
    try:
        if not VT_API_KEY:
            log.warning("⚠️ VT_API_KEY 미설정 → run() 스킵")
            return

        targets = choose_targets(limit=limit)
        if not targets:
            log.info("[VT] 처리할 신규 URL 없음")
            return

        log.info(f"[VT] 시작: {len(targets)}/{limit} URLs")
        done = []
        for url in targets:
            try:
                rep = vt_get_url_report(url)
                name = f"url__{b64url_no_pad(url.encode())}"
                save_json(name, rep)
                done.append(url)
            except Exception as e:
                log.exception(f"[VT] URL 처리 실패: {url} - {e}")
        if done:
            mark_seen(done)
        log.info("[VT] 완료")
    except Exception as e:
        log.exception(e)
        # orchestrator가 죽지 않도록 예외 전파하지 않음

# ─────────────────────────────────────────────────────
# CLI (기존 스크립트 기능 유지)
# ─────────────────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(description="VirusTotal API Collector")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--url", help="분석할 URL")
    g.add_argument("--domain", help="분석할 도메인")
    g.add_argument("--ip", help="분석할 IP")
    g.add_argument("--hash", help="분석할 파일 SHA256")
    p.add_argument("--limit", type=int, default=4, help="RSS 기반 자동 수집 시 처리 개수")
    args = p.parse_args()

    try:
        if args.url:
            log.info(f"🔍 URL: {args.url}")
            data = vt_get_url_report(args.url)
            save_json(f"url__{b64url_no_pad(args.url.encode())}", data)
        elif args.domain:
            log.info(f"🔍 Domain: {args.domain}")
            data = vt_get_domain_report(args.domain)
            save_json(f"domain__{args.domain}", data)
        elif args.ip:
            log.info(f"🔍 IP: {args.ip}")
            data = vt_get_ip_report(args.ip)
            save_json(f"ip__{args.ip}", data)
        elif args.hash:
            log.info(f"🔍 File: {args.hash}")
            data = vt_get_file_report(args.hash)
            save_json(f"hash__{args.hash}", data)
        else:
            # 기본 동작: RSS에서 limit개 자동 처리
            run(limit=args.limit)
        log.info("🎉 완료")
    except requests.HTTPError as http_err:
        log.error(f"HTTP 오류: {http_err}")
    except Exception as e:
        log.error(f"예외 발생: {e}", exc_info=True)

if __name__ == "__main__":
    main()
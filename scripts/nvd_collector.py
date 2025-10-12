#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
nvd_collector.py
- NVD API v2.0 대량 수집 안정화 스크립트
- 기능: 헤더형 API 키, UTC-aware + 'Z' 포맷, pub→lastMod 폴백, 윈도우(청크) 수집, 재시작/복구, 병합 저장
- 사용 예:
    python scripts/nvd_collector.py --start 2020-01-01 --end 2025-10-11 --window-days 30
"""

import os
import sys
import json
import time
import logging
import argparse
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional

import requests
from dotenv import load_dotenv

# ------------------ 설정 ------------------

# 1) 프로젝트 루트 경로 고정 (scripts/의 상위)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 2) 루트 .env를 명시적으로 로드
DOTENV_PATH = os.path.join(BASE_DIR, ".env")
load_dotenv(dotenv_path=DOTENV_PATH)

# 3) API 및 경로
API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = os.getenv("NVD_API_KEY")

# 4) 출력 폴더: 루트/data/nvd_cve
OUT_DIR = os.path.join(BASE_DIR, "data", "nvd_cve")
os.makedirs(OUT_DIR, exist_ok=True)

# 5) 로깅
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logging.info(f"🔑 NVD_API_KEY loaded: {'YES' if API_KEY else 'NO'}")

# 6) 레이트/재시도
DEFAULT_SLEEP_SECONDS = 3.0   # 요청 간 최소 슬립
MAX_PER_WINDOW_RETRIES = 5    # 페이지 요청 재시도 횟수
BACKOFF_BASE = 2.0            # 지수 백오프 base


# ------------------ 유틸 ------------------

def iso_utc_z(dt: datetime) -> str:
    """UTC-aware datetime -> 'YYYY-MM-DDTHH:MM:SS.000Z'"""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def build_headers() -> Dict[str, str]:
    """NVD 권장: apiKey는 헤더로 전달"""
    h = {
        "User-Agent": "PBL-LLM-IDSRules/1.0 (+https://example.invalid)",
        "Accept": "application/json",
    }
    if API_KEY:
        h["apiKey"] = API_KEY
    masked = dict(h)
    if masked.get("apiKey"):
        masked["apiKey"] = "***" + masked["apiKey"][-6:]
    logging.info(f"↗️  headers(check): {masked}")
    return h


def _safe_log_body(resp: requests.Response):
    logging.info("💡 응답 본문:")
    try:
        logging.info(json.dumps(resp.json(), indent=2, ensure_ascii=False))
    except Exception:
        logging.info((resp.text or "")[:1000])


# ------------------ 파라미터 빌더 (pub / lastMod) ------------------

def build_params_by_mode(start_dt: datetime, end_dt: datetime, mode: str, start_index: int = 0, results_per_page: int = 2000) -> Dict[str, Any]:
    """
    mode: "pub" | "lastmod"
    """
    start_z = iso_utc_z(start_dt)
    end_z   = iso_utc_z(end_dt)

    params = {
        "resultsPerPage": results_per_page,
        "startIndex": start_index,
    }
    if mode == "lastmod":
        params["lastModStartDate"] = start_z
        params["lastModEndDate"]   = end_z
    else:
        params["pubStartDate"] = start_z
        params["pubEndDate"]   = end_z
    return params


# ------------------ 핵심: 단일 페이지 호출 ------------------

def fetch_cve_page(params: Dict[str, Any], timeout: int = 30) -> (Optional[Dict[str, Any]], int):
    headers = build_headers()
    try:
        r = requests.get(API_URL, params=params, headers=headers, timeout=timeout)
        logging.info(f"📡 요청: startIndex={params.get('startIndex')} status={r.status_code}")
        if r.status_code == 403:
            logging.error("❌ 403 Forbidden - API 키/헤더 형식 확인 필요")
            _safe_log_body(r); return None, 403
        if r.status_code == 404:
            logging.warning("⚠️ 404 - 해당 기간에 데이터 없음 또는 파라미터 이슈")
            _safe_log_body(r); return None, 404
        if r.status_code != 200:
            logging.error(f"❌ 요청 실패: HTTP {r.status_code}")
            _safe_log_body(r); return None, r.status_code
        if not r.text:
            logging.warning("⚠️ 200 OK지만 본문이 비어있음")
            return None, 200
        return r.json(), 200
    except requests.exceptions.RequestException as e:
        logging.error(f"❌ 네트워크 예외: {e}")
        return None, -1
    except Exception as e:
        logging.error(f"❌ 예외: {e}")
        return None, -2


# ------------------ 윈도우 단위 수집 (pub → lastMod 폴백) ------------------

def fetch_window(start_dt: datetime, end_dt: datetime, sleep_seconds: float = DEFAULT_SLEEP_SECONDS) -> List[Dict[str, Any]]:
    modes = ["pub", "lastmod"]  # 필요하면 ["lastmod", "pub"]로
    results: List[Dict[str, Any]] = []
    results_per_page = 2000

    for mode in modes:
        logging.info(f"🔎 윈도우 수집 시작[{mode}]: {start_dt.isoformat()} ~ {end_dt.isoformat()}")
        results.clear()
        start_index = 0

        while True:
            params = build_params_by_mode(start_dt, end_dt, mode=mode,
                                          start_index=start_index, results_per_page=results_per_page)

            attempt = 0
            while attempt < MAX_PER_WINDOW_RETRIES:
                payload, status = fetch_cve_page(params)

                # 404면 즉시 이 모드 포기하고 다음 모드로 폴백
                if status == 404:
                    logging.warning(f"   [{mode}] 404 → 즉시 폴백")
                    attempt = MAX_PER_WINDOW_RETRIES  # 바깥 while 탈출
                    break

                if payload is None:
                    attempt += 1
                    sleep_time = (BACKOFF_BASE ** attempt)
                    logging.warning(f"   [{mode}] 재시도 {attempt}/{MAX_PER_WINDOW_RETRIES} - {sleep_time:.1f}s 대기")
                    time.sleep(sleep_time)
                    continue

                vulns = payload.get("vulnerabilities", [])
                total = payload.get("totalResults", 0)
                results.extend(vulns)
                logging.info(f"   [{mode}] 페이지: got={len(vulns)}, totalResults={total}, acc={len(results)}")

                if not vulns or len(results) >= total:
                    if len(results) == 0:
                        logging.info(f"   [{mode}] 결과 0건. 다음 모드로 폴백.")
                        attempt = MAX_PER_WINDOW_RETRIES
                        break
                    return results

                start_index += len(vulns)
                params["startIndex"] = start_index
                time.sleep(max(1.0, sleep_seconds))
                break  # 다음 페이지로

            # 재시도 한계 도달 또는 404로 즉시 폴백 → 현재 모드 종료, 다음 모드로
            if attempt >= MAX_PER_WINDOW_RETRIES:
                break

        # 다음 모드로 계속
        continue

    logging.error("❌ pub/lastmod 모두 수집 실패")
    return []


# ------------------ 저장/병합/복구 ------------------

def window_filename(start_dt: datetime, end_dt: datetime) -> str:
    return os.path.join(OUT_DIR, f"window_{start_dt.strftime('%Y%m%d')}_{end_dt.strftime('%Y%m%d')}.json")


def save_window(vulns: List[Dict[str, Any]], start_dt: datetime, end_dt: datetime):
    path = window_filename(start_dt, end_dt)
    payload = {
        "metadata": {
            "collected_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "start_date": iso_utc_z(start_dt),
            "end_date": iso_utc_z(end_dt),
            "count": len(vulns)
        },
        "vulnerabilities": vulns
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    logging.info(f"💾 윈도우 저장: {path} ({len(vulns)}건)")


def load_window_file(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"❌ 윈도우 파일 로드 실패: {path} - {e}")
        return None


def merge_saved_windows(output_filename: Optional[str] = None) -> str:
    window_files = sorted([os.path.join(OUT_DIR, p)
                           for p in os.listdir(OUT_DIR)
                           if p.startswith("window_") and p.endswith(".json")])
    merged: Dict[str, Dict[str, Any]] = {}
    for wf in window_files:
        data = load_window_file(wf)
        if not data:
            continue
        for v in data.get("vulnerabilities", []):
            cve_id = v.get("cve", {}).get("id")
            if cve_id:
                merged.setdefault(cve_id, v)
            else:
                merged[f"noid_{len(merged)}"] = v
    merged_list = list(merged.values())
    if not output_filename:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output_filename = os.path.join(OUT_DIR, f"nvd_merged_{ts}.json")
    payload = {
        "metadata": {
            "merged_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "source_windows": len(window_files),
            "total_count": len(merged_list)
        },
        "vulnerabilities": merged_list
    }
    with open(output_filename, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    logging.info(f"✅ 병합 저장 완료: {output_filename} ({len(merged_list)}건 from {len(window_files)} 윈도우)")
    return output_filename


# ------------------ 전체 윈도우 수집 제어 ------------------

def windowed_collect_and_save(global_start: datetime, global_end: datetime, window_days: int = 30, sleep_between_windows: float = DEFAULT_SLEEP_SECONDS):
    """
    global_start ~ global_end 범위를 window_days 단위로 쪼개서 수집.
    이미 존재하는 윈도우 파일은 건너뜀 → 안전한 재시작 지원
    """
    assert global_start.tzinfo is not None and global_end.tzinfo is not None, "UTC-aware datetimes required"
    cur_start = global_start
    window_idx = 0
    all_counts = 0

    while cur_start <= global_end:
        window_idx += 1
        cur_end = min(cur_start + timedelta(days=window_days) - timedelta(seconds=1), global_end)
        path = window_filename(cur_start, cur_end)
        logging.info(f"🔁 윈도우#{window_idx}: {cur_start.isoformat()} ~ {cur_end.isoformat()} -> 파일: {os.path.basename(path)}")

        if os.path.exists(path):
            data = load_window_file(path)
            cnt = (data.get("metadata", {}).get("count") if data else None)
            logging.info(f"   -> 이미 존재: {os.path.basename(path)} ({cnt if cnt is not None else 'unknown'}건), 건너뜀")
        else:
            vulns = fetch_window(cur_start, cur_end, sleep_seconds=sleep_between_windows)
            save_window(vulns, cur_start, cur_end)
            all_counts += len(vulns)

        time.sleep(max(1.0, sleep_between_windows))
        cur_start = cur_end + timedelta(seconds=1)

    logging.info(f"🎯 전체 윈도우 완료 (총 추가 수집 건수 약): {all_counts}")
    merged_path = merge_saved_windows()
    logging.info(f"🎉 완료: 병합파일 -> {merged_path}")
    return merged_path


# ------------------ API 연결 테스트 ------------------

def test_api_connection():
    """
    최근 7일 테스트. 경계 이슈 회피 위해 end = now-2h 사용.
    pub에서 404/빈응답이면 자동으로 lastMod로 폴백.
    """
    if not API_KEY:
        logging.warning("⚠️ NVD_API_KEY 환경변수 비어있음. 헤더 없이 요청 시 rate limit 작음.")
    end = datetime.now(timezone.utc) - timedelta(hours=2)
    start = end - timedelta(days=7)
    logging.info("🧪 API 연결 테스트(최근 7일, end=now-2h)")
    sample = fetch_window(start, end, sleep_seconds=DEFAULT_SLEEP_SECONDS)
    if sample:
        logging.info(f"✅ 테스트 성공: {len(sample)}건 수집(샘플) - OK")
        sids = [v.get("cve", {}).get("id", "") for v in sample[:3]]
        logging.info(f"   샘플 CVE: {sids}")
        return True
    else:
        logging.error("❌ 테스트 실패: 데이터 수집 불가 (로그 확인)")
        return False


# ------------------ CLI ------------------

def parse_args():
    p = argparse.ArgumentParser(description="NVD windowed collector")
    p.add_argument("--start", required=True, help="수집 시작일 (YYYY-MM-DD) - UTC 기준")
    p.add_argument("--end", required=True, help="수집 종료일 (YYYY-MM-DD) - UTC 기준")
    p.add_argument("--window-days", type=int, default=30, help="윈도우 크기 (일)")
    p.add_argument("--sleep", type=float, default=DEFAULT_SLEEP_SECONDS, help="요청간 최소 슬립(초)")
    return p.parse_args()


def iso_date_to_utc_dt(s: str) -> datetime:
    # 'YYYY-MM-DD' -> datetime with tz=UTC at 00:00:00
    return datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=timezone.utc)


# ------------------ 엔트리포인트 ------------------

if __name__ == "__main__":
    args = parse_args()
    global_start = iso_date_to_utc_dt(args.start)
    global_end = iso_date_to_utc_dt(args.end).replace(hour=23, minute=59, second=59)

    logging.info("=" * 60)
    logging.info("🚀 NVD Windowed Collector 시작")
    logging.info(f"   start={global_start.isoformat()}  end={global_end.isoformat()}  window_days={args.window_days}  sleep={args.sleep}")
    logging.info("=" * 60)

    ok = test_api_connection()
    if not ok:
        logging.error("🔚 연결 테스트 실패: 환경변수/API 상태/네트워크/기간 경계 확인 필요")
        sys.exit(1)

    merged_path = windowed_collect_and_save(global_start, global_end, window_days=args.window_days, sleep_between_windows=args.sleep)
    logging.info(f"완료: merged output -> {merged_path}")
#!/usr/bin/env python3
"""
VirusTotal v3 연동 스크립트
- URL: 캐시 없으면 스캔 등록 → 분석 완료 폴링 → 최종 리포트 저장
- Domain/IP/Hash: 즉시 조회
- 결과 JSON 파일 저장
"""

import os
import json
import time
import argparse
import logging
import base64
from urllib.parse import urlparse
import requests
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
if not VT_API_KEY:
    raise RuntimeError("⚠️ VT_API_KEY 환경변수가 설정되어 있지 않습니다. (.env 또는 환경변수 등록 필요)")

HEADERS = {"x-apikey": VT_API_KEY}
OUT_DIR = "data/virustotal"
os.makedirs(OUT_DIR, exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("vt")

# -----------------------------
# 공통 유틸
# -----------------------------
def save_json(name: str, data: dict) -> str:
    safe = name.replace("/", "_").replace(":", "_")
    path = os.path.join(OUT_DIR, f"{safe}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    log.info(f"✅ 저장 완료: {path}")
    return path

def base64url_no_padding(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

# -----------------------------
# URL 조회 흐름 (권장)
# -----------------------------
def vt_get_url_report(url: str) -> dict:
    """URL 리포트 가져오기 (캐시 없으면 스캔 후 폴링)"""
    url_id = base64url_no_padding(url.encode("utf-8"))
    get_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    r = requests.get(get_url, headers=HEADERS, timeout=30)
    if r.status_code == 200:
        return r.json()

    if r.status_code != 404:
        # 401/403/429 등
        log.error(f"❌ URL 조회 실패: status={r.status_code} body={r.text}")
        r.raise_for_status()

    # 404 → VT에 캐시 없음 → 스캔 등록
    log.info("ℹ️ 캐시 없음 → URL 스캔 등록 중 (POST /urls)")
    analysis_id = vt_submit_url(url)

    # 분석 완료까지 폴링
    vt_poll_analysis(analysis_id)

    # 완료 후 다시 최종 리포트 조회
    r2 = requests.get(get_url, headers=HEADERS, timeout=30)
    if r2.status_code != 200:
        log.error(f"❌ 최종 리포트 조회 실패: status={r2.status_code} body={r2.text}")
        r2.raise_for_status()
    return r2.json()

def vt_submit_url(url: str) -> str:
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
    log.info(f"📝 분석 등록 완료: analysis_id={analysis_id}")
    return analysis_id

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

# -----------------------------
# 도메인 / IP / 파일 해시
# -----------------------------
def vt_get_domain_report(domain: str) -> dict:
    r = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=HEADERS, timeout=30)
    if r.status_code != 200:
        log.error(f"❌ 도메인 조회 실패: status={r.status_code} body={r.text}")
        r.raise_for_status()
    return r.json()

def vt_get_ip_report(ip: str) -> dict:
    r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=HEADERS, timeout=30)
    if r.status_code != 200:
        log.error(f"❌ IP 조회 실패: status={r.status_code} body={r.text}")
        r.raise_for_status()
    return r.json()

def vt_get_file_report(sha256: str) -> dict:
    r = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256}", headers=HEADERS, timeout=30)
    if r.status_code != 200:
        log.error(f"❌ 파일 해시 조회 실패: status={r.status_code} body={r.text}")
        r.raise_for_status()
    return r.json()

# -----------------------------
# CLI
# -----------------------------
def main():
    p = argparse.ArgumentParser(description="VirusTotal API Collector")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--url", help="분석할 URL")
    g.add_argument("--domain", help="분석할 도메인")
    g.add_argument("--ip", help="분석할 IP")
    g.add_argument("--hash", help="분석할 파일 SHA256")
    args = p.parse_args()

    try:
        if args.url:
            log.info(f"🔍 VirusTotal URL 검사: {args.url}")
            data = vt_get_url_report(args.url)
            save_json(f"url__{base64url_no_padding(args.url.encode())}", data)
        elif args.domain:
            log.info(f"🔍 VirusTotal 도메인 검사: {args.domain}")
            data = vt_get_domain_report(args.domain)
            save_json(f"domain__{args.domain}", data)
        elif args.ip:
            log.info(f"🔍 VirusTotal IP 검사: {args.ip}")
            data = vt_get_ip_report(args.ip)
            save_json(f"ip__{args.ip}", data)
        elif args.hash:
            log.info(f"🔍 VirusTotal 파일 해시 검사: {args.hash}")
            data = vt_get_file_report(args.hash)
            save_json(f"hash__{args.hash}", data)
        else:
            # 기본 테스트: URL
            test_url = "http://example.com"
            log.info(f"🔍 (기본) VirusTotal URL 검사: {test_url}")
            data = vt_get_url_report(test_url)
            save_json(f"url__{base64url_no_padding(test_url.encode())}", data)

        log.info("🎉 완료")
    except requests.HTTPError as http_err:
        log.error(f"HTTP 오류: {http_err}")
    except Exception as e:
        log.error(f"예외 발생: {e}", exc_info=True)

if __name__ == "__main__":
    main()
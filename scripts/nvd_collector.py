#!/usr/bin/env python3
import os
import json
import time
import logging
from datetime import datetime
import requests
from dotenv import load_dotenv

load_dotenv()

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = os.getenv("NVD_API_KEY")
OUT_DIR = "data/nvd_cve"
os.makedirs(OUT_DIR, exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

COMMON_HEADERS = {
    # CDN 회피 + JSON 강제
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0 Safari/537.36"
    ),
    "Accept": "application/json",
}

def fetch_cve_data(start_date: datetime, end_date: datetime):
    all_results = []
    start_index = 0
    results_per_page = 200

    # 헤더에 apiKey 첨부 (쿼리스트링 X)
    headers = dict(COMMON_HEADERS)
    if API_KEY:
        headers["apiKey"] = API_KEY

    while True:
        params = {
            "resultsPerPage": results_per_page,
            "startIndex": start_index,
            "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        }

        logging.info(f"📡 요청 중... startIndex={start_index}")
        r = requests.get(API_URL, params=params, headers=headers, timeout=30)

        if r.status_code != 200:
            logging.error("❌ 요청 실패: status=%s", r.status_code)
            logging.error("요청 URL: %s", r.url)
            # 응답 본문까지 찍어서 원인 확인
            try:
                logging.error("응답 본문: %s", r.text[:1000])
            except Exception:
                pass
            return []

        data = r.json()
        vuln_list = data.get("vulnerabilities", [])
        total = data.get("totalResults", 0)

        all_results.extend(vuln_list)
        logging.info(f"  ↳ 현재까지 {len(all_results)}/{total} 수집")

        if len(all_results) >= total:
            break

        start_index += results_per_page
        time.sleep(1)

    return all_results

def save_cve_data(vulns, start_date, end_date):
    filename = f"nvd_{start_date.strftime('%Y%m%d')}_{end_date.strftime('%Y%m%d')}.json"
    path = os.path.join(OUT_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(vulns, f, ensure_ascii=False, indent=2)
    logging.info(f"✅ 저장 완료: {path} ({len(vulns)}건)")

if __name__ == "__main__":
    # 검증용: 2024-09-01 ~ 2024-09-03 (curl로도 잘 나오는 기간)
    start = datetime(2024, 9, 1, 0, 0, 0)
    end   = datetime(2024, 9, 3, 23, 59, 59)

    vulns = fetch_cve_data(start, end)
    if vulns:
        save_cve_data(vulns, start, end)
    else:
        logging.warning("⚠️ 수집된 취약점이 없습니다.")
#!/usr/bin/env python3
"""
RSS 피드 자동 수집 스크립트 (DB 연동 버전)
- (수정) datetime.UTC 임포트 오류 수정
"""

import os
import sys
import time
from datetime import datetime, timezone # <-- 수정된 부분!
import hashlib
import json
import argparse
import logging
from urllib.parse import urlparse
from typing import List, Dict, Optional

# --- ▼▼▼ 프로젝트 루트 경로 설정 (가장 중요!) ▼▼▼ ---
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.append(project_root)
# --- ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲ ---

import feedparser
from core.parser import get_text_from_url
import utils.db as db

# ============================================================
# 설정
# ============================================================
RSS_FEEDS = {
    "NVD Analyzed": "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml",
    # "ZDI All": "https://www.zerodayinitiative.com/rss/alladvisories/",
    "Cloudflare Blog": "https://blog.cloudflare.com/rss/",
    # "DailySecu": "https://www.dailysecu.com/rss/all.xml",
    # 1. 정부 기관 (필수)
    "CISA Alerts": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "CERT-KR": "https://www.krcert.or.kr/rss.do?data_id=01",
    
    # 2. 주요 보안 업체 (강력 추천)
    "Mandiant (Google)": "https://cloud.google.com/blog/topics/threat-intelligence/rss",
    "Palo Alto (Unit 42)": "https://unit42.paloaltonetworks.com/feed/",
    "CrowdStrike": "https://www.crowdstrike.com/blog/feed/",
    "Microsoft Security": "https://www.microsoft.com/en-us/security/blog/feed/",
    "Rapid7 (AttackerKB)": "https://attackerkb.com/rss",
    
    # 3. 유명 보안 뉴스/블로그
    "The Hacker News": "https://feeds.feedburner.com/TheHackerNews",
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
    "Bleeping Computer": "https://www.bleepingcomputer.com/feed/",
    "Schneier on Security": "https://www.schneier.com/feed/",
}
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "rss_collector.log")
COLLECTION_INTERVAL = 1800
MAX_RETRIES = 3
RETRY_DELAY = 5

# ============================================================
# 디렉토리 및 로깅 설정
# ============================================================
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# ============================================================
# 유틸리티 함수
# ============================================================
def parse_published_date(entry):
    """feedparser의 published_parsed를 datetime 객체로 변환"""
    if hasattr(entry, 'published_parsed') and entry.published_parsed:
        try:
            return datetime.fromtimestamp(time.mktime(entry.published_parsed))
        except Exception:
            pass
    if hasattr(entry, 'updated_parsed') and entry.updated_parsed:
        try:
            return datetime.fromtimestamp(time.mktime(entry.updated_parsed))
        except Exception:
            pass
    return datetime.now() # <-- 이제 정상 작동합니다.

# ============================================================
# RSS 피드 처리
# ============================================================
def fetch_feed_with_retry(feed_url: str, max_retries: int = MAX_RETRIES) -> Optional[feedparser.FeedParserDict]:
    """재시도 로직이 포함된 피드 가져오기"""
    for attempt in range(max_retries):
        try:
            logger.info(f"피드 가져오는 중: {feed_url} (시도 {attempt + 1}/{max_retries})")
            feed = feedparser.parse(feed_url)
            if feed.bozo:
                logger.warning(f"피드 파싱 경고: {feed.bozo_exception}")
            return feed
        except Exception as e:
            logger.error(f"피드 가져오기 실패 (시도 {attempt + 1}): {e}")
            if attempt < max_retries - 1:
                time.sleep(RETRY_DELAY)
    return None

def process_entry(entry, site_name: str) -> bool:
    """RSS 엔트리 하나를 처리하여 DB에 저장"""
    url = entry.get('link', '')
    if not url:
        logger.warning("링크가 없는 엔트리 스킵")
        return False
    
    title = entry.get("title", "제목 없음")
    published_date = parse_published_date(entry)

    try:
        db.add_cti_post(
            title=title,
            link=url,
            site_name=site_name,
            published_date=published_date
        )
        return True
    except Exception as e:
        if "UNIQUE constraint failed" in str(e):
             logger.debug(f"중복된 CTI 링크 (무시): {url}")
             return True
        else:
             logger.error(f"❌ DB 저장 실패 ({url}): {e}")
             return False

def process_feed(feed_url: str, site_name: str) -> Dict:
    """단일 RSS 피드 처리"""
    logger.info(f"\n{'='*60}")
    logger.info(f"처리 시작: {site_name} ({feed_url})")
    logger.info(f"{'='*60}")
    
    feed = fetch_feed_with_retry(feed_url)
    if not feed:
        logger.error(f"피드 가져오기 실패: {feed_url}")
        return {"success": 0, "failed": 0, "total": 0}
    
    entries = feed.entries
    total_entries = len(entries)
    logger.info(f"발견된 엔트리 수: {total_entries}")
    
    if not entries:
        return {"success": 0, "failed": 0, "total": 0}
    
    stats = {"success": 0, "failed": 0, "total": total_entries}
    
    for i, entry in enumerate(entries, 1):
        logger.debug(f"[{i}/{total_entries}] 처리 중: {entry.get('title', '')}")
        result = process_entry(entry, site_name)
        
        if result:
            stats["success"] += 1
        else:
            stats["failed"] += 1
    
    logger.info(f"피드 처리 완료: {site_name}")
    logger.info(f"  총 {stats['total']}개 중 {stats['success']}개 처리 (성공/중복 포함), {stats['failed']}개 실패")
    
    return stats

# ============================================================
# 메인 수집 함수
# ============================================================
def collect_all_sources() -> Dict:
    """모든 RSS 피드 수집"""
    logger.info("\n" + "="*80)
    logger.info("RSS (CTI List) 수집 시작")
    # --- ▼▼▼▼▼ 수정된 부분 ▼▼▼▼▼ ---
    logger.info(f"시작 시간: {datetime.now(timezone.utc).isoformat()}")
    # --- ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲ ---
    logger.info("="*80)
    
    total_stats = {"success": 0, "failed": 0, "total": 0}
    
    for site_name, feed_url in RSS_FEEDS.items():
        try:
            stats = process_feed(feed_url, site_name)
            for key in total_stats:
                total_stats[key] += stats[key]
        except Exception as e:
            logger.error(f"피드 처리 중 예외 발생 ({feed_url}): {e}", exc_info=True)
    
    logger.info("\n" + "="*80)
    logger.info("RSS 수집 완료")
    # --- ▼▼▼▼▼ 수정된 부분 ▼▼▼▼▼ ---
    logger.info(f"종료 시간: {datetime.now(timezone.utc).isoformat()}")
    # --- ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲ ---
    logger.info(f"총 {total_stats['total']}개 항목 발견, {total_stats['success']}개 DB 저장 성공(중복 포함), {total_stats['failed']}개 실패")
    logger.info("="*80)
    
    return total_stats

# ============================================================
# 메인 실행
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="RSS 피드 자동 수집 스크립트 (DB 저장용)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python scripts/rss_collector.py             # 데몬 모드 (무한 반복)
  python scripts/rss_collector.py --once      # 1회만 실행
        """
    )
    parser.add_argument("--once", action="store_true", help="수집 1회만 실행하고 종료")
    parser.add_argument("--interval", type=int, default=COLLECTION_INTERVAL, help=f"수집 주기 (초, 기본값: {COLLECTION_INTERVAL})")
    parser.add_argument("--debug", action="store_true", help="디버그 모드 (상세 로그 출력)")
    
    args = parser.parse_args()
    
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    logger.info("DB 연결 및 초기화 확인...")
    db.init_db()
    
    loop = not args.once
    
    logger.info("="*80)
    logger.info("RSS 수집기 시작")
    logger.info(f"모드: {'데몬 (무한 반복)' if loop else '1회 실행'}")
    if loop:
        logger.info(f"수집 주기: {args.interval}초 ({args.interval // 60}분)")
    logger.info(f"로그 파일: {LOG_FILE}")
    logger.info(f"DB 파일: {db.DB_FILE}")
    logger.info("="*80 + "\n")
    
    try:
        if loop:
            run_count = 0
            while True:
                run_count += 1
                logger.info(f"\n{'#'*80}")
                logger.info(f"수집 실행 #{run_count}")
                logger.info(f"{'#'*80}")
                
                try:
                    collect_all_sources()
                except Exception as e:
                    logger.error(f"수집 중 예외 발생: {e}", exc_info=True)
                
                logger.info(f"\n다음 실행까지 {args.interval}초 대기 중...")
                time.sleep(args.interval)
        else:
            collect_all_sources()
            logger.info("\n수집 완료. 프로그램을 종료합니다.")
    
    except KeyboardInterrupt:
        logger.info("\n\n사용자에 의해 중단되었습니다.")
    except Exception as e:
        logger.error(f"\n치명적 오류 발생: {e}", exc_info=True)
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
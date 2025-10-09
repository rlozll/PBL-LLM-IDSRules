#!/usr/bin/env python3
"""
RSS 피드 자동 수집 스크립트
- 주기적으로 RSS 피드를 크롤링하여 본문 텍스트 추출
- 중복 방지 및 에러 핸들링
- 데몬 모드 지원
"""

import os
import time
import datetime
import hashlib
import json
import argparse
import logging
from urllib.parse import urlparse
from typing import List, Dict, Optional

import feedparser
from core.parser import get_text_from_url

# ============================================================
# 설정
# ============================================================
RSS_FEEDS = [
    "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml",
    "https://www.zerodayinitiative.com/rss/alladvisories/",
    "https://blog.cloudflare.com/rss/",
    # 추가 피드는 여기에
]

OUT_DIR = "data/rss_parsed"
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "rss_collector.log")
STATE_FILE = os.path.join(OUT_DIR, ".collection_state.json")

# 수집 주기 (초)
COLLECTION_INTERVAL = 3600  # 1시간

# 재시도 설정
MAX_RETRIES = 3
RETRY_DELAY = 5  # 초

# 최소 텍스트 길이
MIN_TEXT_LENGTH = 100

# ============================================================
# 디렉토리 생성
# ============================================================
os.makedirs(OUT_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# ============================================================
# 로깅 설정
# ============================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# ============================================================
# 유틸리티 함수
# ============================================================
def sanitize(s: str) -> str:
    """파일명에 안전한 문자열로 변환"""
    return "".join(c if c.isalnum() or c in ('-', '_') else "-" for c in s)


def load_state() -> Dict:
    """수집 상태 로드 (마지막 수집 시간, 처리된 URL 등)"""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"상태 파일 로드 실패: {e}")
    return {
        "last_run": None,
        "processed_urls": [],
        "total_collected": 0,
        "failed_urls": []
    }


def save_state(state: Dict) -> None:
    """수집 상태 저장"""
    try:
        with open(STATE_FILE, 'w') as f:
            json.dump(state, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.error(f"상태 파일 저장 실패: {e}")


def get_url_hash(url: str) -> str:
    """URL의 고유 해시 생성"""
    return hashlib.md5(url.encode()).hexdigest()[:12]


# ============================================================
# RSS 피드 처리
# ============================================================
def fetch_feed_with_retry(feed_url: str, max_retries: int = MAX_RETRIES) -> Optional[feedparser.FeedParserDict]:
    """재시도 로직이 포함된 피드 가져오기"""
    for attempt in range(max_retries):
        try:
            logger.info(f"피드 가져오는 중: {feed_url} (시도 {attempt + 1}/{max_retries})")
            feed = feedparser.parse(feed_url)
            
            if feed.bozo:  # 파싱 에러 체크
                logger.warning(f"피드 파싱 경고: {feed.bozo_exception}")
            
            return feed
        except Exception as e:
            logger.error(f"피드 가져오기 실패 (시도 {attempt + 1}): {e}")
            if attempt < max_retries - 1:
                time.sleep(RETRY_DELAY)
    
    return None


def process_entry(entry, source_domain: str, state: Dict) -> bool:
    """RSS 엔트리 하나를 처리"""
    url = entry.get('link', '')
    if not url:
        logger.warning("링크가 없는 엔트리 스킵")
        return False
    
    # 중복 체크
    url_hash = get_url_hash(url)
    if url in state['processed_urls']:
        logger.debug(f"이미 처리된 URL 스킵: {url}")
        return False
    
    # 출력 파일 경로
    out_path = os.path.join(OUT_DIR, f"{sanitize(source_domain)}-{url_hash}.json")
    if os.path.exists(out_path):
        logger.debug(f"파일 이미 존재: {out_path}")
        state['processed_urls'].append(url)
        return False
    
    # 본문 추출
    try:
        logger.info(f"본문 추출 중: {url}")
        text = get_text_from_url(url)
        
        # 텍스트 길이 체크
        if len(text) < MIN_TEXT_LENGTH:
            logger.warning(f"텍스트 너무 짧음 ({len(text)}자): {url}")
            state['failed_urls'].append({
                "url": url,
                "reason": "text_too_short",
                "length": len(text),
                "timestamp": datetime.datetime.now(datetime.UTC).isoformat()
            })
            return False
        
        # 데이터 구조화
        data = {
            "url": url,
            "source_domain": source_domain,
            "title": entry.get("title", "제목 없음"),
            "summary": entry.get("summary", "")[:500],  # 요약 (최대 500자)
            "published": entry.get("published", ""),
            "collected_at": datetime.datetime.now(datetime.UTC).isoformat(),
            "text_length": len(text),
            "text": text
        }
        
        # 파일 저장
        with open(out_path, "w", encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        
        logger.info(f"✅ 저장 완료: {out_path} ({len(text)}자)")
        
        # 상태 업데이트
        state['processed_urls'].append(url)
        state['total_collected'] += 1
        
        return True
        
    except Exception as e:
        logger.error(f"❌ 처리 실패 ({url}): {e}")
        state['failed_urls'].append({
            "url": url,
            "reason": str(e),
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat()
        })
        return False


def process_feed(feed_url: str, state: Dict) -> Dict:
    """단일 RSS 피드 처리"""
    logger.info(f"\n{'='*60}")
    logger.info(f"처리 시작: {feed_url}")
    logger.info(f"{'='*60}")
    
    feed = fetch_feed_with_retry(feed_url)
    if not feed:
        logger.error(f"피드 가져오기 실패: {feed_url}")
        return {"success": 0, "failed": 0, "skipped": 0}
    
    entries = feed.entries
    logger.info(f"발견된 엔트리 수: {len(entries)}")
    
    if not entries:
        logger.warning(f"엔트리가 없습니다: {feed_url}")
        return {"success": 0, "failed": 0, "skipped": 0}
    
    source_domain = urlparse(feed_url).netloc
    stats = {"success": 0, "failed": 0, "skipped": 0}
    
    for i, entry in enumerate(entries, 1):
        logger.info(f"\n[{i}/{len(entries)}] 처리 중...")
        result = process_entry(entry, source_domain, state)
        
        if result:
            stats["success"] += 1
        else:
            if entry.get('link') in state['processed_urls']:
                stats["skipped"] += 1
            else:
                stats["failed"] += 1
        
        # 서버 부하 방지를 위한 딜레이
        if i < len(entries):
            time.sleep(1)
    
    logger.info(f"\n피드 처리 완료: {feed_url}")
    logger.info(f"  ✅ 성공: {stats['success']}")
    logger.info(f"  ⏭️  스킵: {stats['skipped']}")
    logger.info(f"  ❌ 실패: {stats['failed']}")
    
    return stats


# ============================================================
# 메인 수집 함수
# ============================================================
def collect_all_sources() -> Dict:
    """모든 RSS 피드 수집"""
    logger.info("\n" + "="*80)
    logger.info("RSS 수집 시작")
    logger.info(f"시작 시간: {datetime.datetime.now(datetime.UTC).isoformat()}")
    logger.info("="*80)
    
    state = load_state()
    total_stats = {"success": 0, "failed": 0, "skipped": 0}
    
    for feed_url in RSS_FEEDS:
        try:
            stats = process_feed(feed_url, state)
            for key in total_stats:
                total_stats[key] += stats[key]
        except Exception as e:
            logger.error(f"피드 처리 중 예외 발생 ({feed_url}): {e}")
    
    # 상태 저장
    state['last_run'] = datetime.datetime.now(datetime.UTC).isoformat()
    
    # 실패 URL 목록 관리 (최근 100개만 유지)
    if len(state['failed_urls']) > 100:
        state['failed_urls'] = state['failed_urls'][-100:]
    
    save_state(state)
    
    logger.info("\n" + "="*80)
    logger.info("RSS 수집 완료")
    logger.info(f"종료 시간: {datetime.datetime.now(datetime.UTC).isoformat()}")
    logger.info(f"총 성공: {total_stats['success']}")
    logger.info(f"총 스킵: {total_stats['skipped']}")
    logger.info(f"총 실패: {total_stats['failed']}")
    logger.info(f"누적 수집: {state['total_collected']}")
    logger.info("="*80)
    
    return total_stats


# ============================================================
# 메인 실행
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="RSS 피드 자동 수집 스크립트",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  python rss_collector.py                    # 데몬 모드 (무한 반복)
  python rss_collector.py --once             # 1회만 실행
  python rss_collector.py --interval 7200    # 2시간마다 실행
  RSS_LOOP=0 python rss_collector.py         # 환경변수로 1회 실행
        """
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="수집 1회만 실행하고 종료"
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=COLLECTION_INTERVAL,
        help=f"수집 주기 (초, 기본값: {COLLECTION_INTERVAL})"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="디버그 모드 (상세 로그 출력)"
    )
    
    args = parser.parse_args()
    
    # 디버그 모드 설정
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    # 환경변수 체크
    loop = os.getenv("RSS_LOOP", "1") != "0" and not args.once
    
    logger.info("="*80)
    logger.info("RSS 수집기 시작")
    logger.info(f"모드: {'데몬 (무한 반복)' if loop else '1회 실행'}")
    if loop:
        logger.info(f"수집 주기: {args.interval}초 ({args.interval // 60}분)")
    logger.info(f"출력 디렉토리: {OUT_DIR}")
    logger.info(f"로그 파일: {LOG_FILE}")
    logger.info("="*80 + "\n")
    
    try:
        if loop:
            # 무한 루프 모드
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
                logger.info(f"다음 실행 시간: {(datetime.datetime.now() + datetime.timedelta(seconds=args.interval)).strftime('%Y-%m-%d %H:%M:%S')}")
                time.sleep(args.interval)
        else:
            # 1회 실행 모드
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
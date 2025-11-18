#!/usr/bin/env python3
import os
import sys
import asyncio
import feedparser
import json
import logging
from datetime import datetime, timezone

# --- 프로젝트 루트 경로 설정 ---
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.append(project_root)

# --- 모듈 임포트 ---
import utils.db as db
from core.parser import get_text_from_url
from core.llm_handler import generate_analysis_from_text
from utils.validator import validate_rule

# --- 로깅 설정 ---
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, "bookmark_processor.log"), encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

async def analyze_and_save(site_id, entry):
    """새 글 하나를 분석하고 DB에 저장"""
    link = entry.get('link')
    title = entry.get('title', 'No Title')
    
    if not link: return

    # 1. 중복 체크 (DB에 이미 저장된 URL인지 확인)
    # (효율성을 위해 최근 결과 목록을 가져와서 비교하거나, DB 쿼리로 확인해야 함)
    # 여기서는 간단히 최근 100개를 가져와서 메모리에서 비교
    existing_results = db.get_bookmark_results_list(limit=100)
    if any(r['post_url'] == link for r in existing_results):
        logger.debug(f"SKIP: 이미 분석된 글입니다. ({title})")
        return

    logger.info(f"🚀 새 글 발견! 자동 분석 시작... [{title}]")

    # 2. 파싱
    try:
        text = get_text_from_url(link)
        if len(text) < 50:
            logger.warning(f"FAIL: 본문 추출 실패 (너무 짧음) - {link}")
            return
    except Exception as e:
        logger.error(f"FAIL: 파싱 중 오류 - {e}")
        return

    # 3. LLM 분석 (IoC 추출, Rule 생성, 설명 생성)
    try:
        llm_output = await generate_analysis_from_text(text)
        if llm_output.get("error"):
            logger.error(f"FAIL: LLM 분석 실패 - {llm_output['error']}")
            return
    except Exception as e:
        logger.error(f"FAIL: LLM 호출 중 오류 - {e}")
        return

    # 4. 검증
    rule = llm_output.get("rule", "")
    validation_result = "Skipped"
    validation_details = ""
    
    try:
        # OS 확인 로직 (Windows/Linux)
        if sys.platform == "darwin":
            validation_result = "Skipped on macOS"
        else:
            val_res = validate_rule(rule)
            validation_result = val_res["overall_status"]
            if validation_result == "Failed":
                 validation_details = f"Syntax Error:\n{val_res['syntax_check_output']}"
            elif validation_result == "Warning":
                 validation_details = "Static Warnings:\n" + "\n".join(val_res['static_warnings'])
            else:
                 validation_details = "Syntax OK."
    except Exception as e:
        validation_result = "ValidatorError"
        validation_details = str(e)

    # 5. DB 저장
    result_data = {
        "site_id": site_id,
        "post_url": link,
        "post_title": title,
        "generated_rule": rule,
        "validation_result": validation_result,
        "validation_details": validation_details,
        "extracted_ioc": llm_output.get("ioc", {}),
        "rule_explanation": llm_output.get("explanation", {})
    }
    
    try:
        db.add_bookmark_result(result_data)
        logger.info(f"✅ SUCCESS: 분석 완료 및 DB 저장됨. ({title})")
    except Exception as e:
        logger.error(f"FAIL: DB 저장 실패 - {e}")


async def process_bookmarks_async():
    """북마크된 사이트를 순회하며 새 글을 분석"""
    logger.info("--- 북마크 자동 분석 작업 시작 ---")
    
    # 1. 등록된 사이트 가져오기
    sites = db.get_bookmark_sites()
    if not sites:
        logger.info("등록된 북마크 사이트가 없습니다.")
        return

    for site in sites:
        url = site['url']
        site_id = site['id']
        logger.info(f"CHECKING: {url} (ID: {site_id})")

        try:
            # RSS 파싱
            feed = feedparser.parse(url)
            if not feed.entries:
                logger.warning(f"글이 없거나 RSS가 아닙니다. ({url})")
                continue

            # 테스트를 위해 최신 글 1개만 확인 (실제 운영 시에는 3~5개)
            for entry in feed.entries[:4]: 
                await analyze_and_save(site_id, entry)

        except Exception as e:
            logger.error(f"사이트 처리 중 오류 ({url}) - {e}")

    logger.info("--- 북마크 자동 분석 작업 완료 ---")

def process_bookmarks():
    """스케줄러가 호출할 동기 함수 (asyncio 래퍼)"""
    asyncio.run(process_bookmarks_async())

if __name__ == "__main__":
    # 직접 실행 테스트
    process_bookmarks()
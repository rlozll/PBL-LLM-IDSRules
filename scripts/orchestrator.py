#!/usr/bin/env python3
import os, sys, logging, subprocess
from pathlib import Path
from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.interval import IntervalTrigger

# ---- 공통 부팅 준비
BASE_DIR = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = BASE_DIR / "scripts"
os.chdir(BASE_DIR)
sys.path[:0] = [str(BASE_DIR), str(SCRIPTS_DIR)]

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def run_module(mod: str, args: list[str]) -> int:
    """서브프로세스로 모듈 CLI 실행 (import 시그니처/환경차이 회피)"""
    cmd = [sys.executable, "-m", mod] + args
    return subprocess.run(cmd, cwd=str(BASE_DIR), check=True).returncode

# ---- 잡 정의 (모듈을 함수로 직접 안 부르고 -m CLI로 호출)
def job_rss():
    logging.info("📡 RSS 수집 시작")
    try:
        # 1회만 실행 (중복 방지/상태 관리 내부 구현 사용)
        run_module("scripts.collectors.rss_collector", ["--once"])
    except Exception:
        logging.exception("RSS 수집 실패")
    logging.info("✅ RSS 수집 종료")

def job_api():
    logging.info("🗂️ API 수집 시작")
    try:
        # 사용자 정의 api_collector가 있으면 우선 실행
        try:
            run_module("scripts.collectors.api_collector", [])
        except Exception:
            # 폴백: 최근 2일 NVD 윈도우(1일)로 수집
            from datetime import datetime, timedelta, timezone
            end = datetime.now(timezone.utc) - timedelta(hours=2)
            start = end - timedelta(days=2)
            run_module("scripts.collectors.nvd_collector", [
                "--start", start.strftime("%Y-%m-%d"),
                "--end",   end.strftime("%Y-%m-%d"),
                "--window-days", "1"
            ])
    except Exception:
        logging.exception("API 수집 실패")
    logging.info("✅ API 수집 종료")

def job_vt():
    logging.info("🧬 VirusTotal 검사 시작")
    try:
        # 큐에서 최대 4건 처리 (너가 이미 --limit 지원 확인함)
        run_module("scripts.collectors.virustotal_collector", ["--limit", "4"])
    except Exception:
        logging.exception("VirusTotal 검사 실패")
    logging.info("✅ VirusTotal 검사 종료")

if __name__ == "__main__":
    sched = BlockingScheduler(timezone="Asia/Seoul")
    sched.add_job(job_rss, IntervalTrigger(minutes=10), id="rss", coalesce=True)
    sched.add_job(job_api, IntervalTrigger(hours=2),     id="api", coalesce=True)
    sched.add_job(job_vt,  IntervalTrigger(minutes=1),   id="vt",  coalesce=True)

    logging.info("🕒 Scheduler 시작됨 (RSS=10분, API=2시간, VT=1분)")
    for j in sched.get_jobs():
        logging.info(f"[JOB] {j.id} trigger={j.trigger}")

    try:
        sched.start()
    except (KeyboardInterrupt, SystemExit):
        logging.info("👋 종료 신호 수신, 스케줄러 종료")

# utils/db.py

import sqlite3
import json
import datetime
from typing import List, Dict, Any

# DB 파일 이름 (프로젝트 루트에 생성됨)
DB_FILE = "cti_dashboard.db"

def get_db_connection():
    """DB 연결 객체를 반환합니다."""
    conn = sqlite3.connect(DB_FILE)
    # 딕셔너리 형태로 결과를 받기 위해 row_factory 설정
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """
    프로그램 시작 시 호출되어, 필요한 모든 테이블을 생성합니다.
    """
    create_table_sql = """
    CREATE TABLE IF NOT EXISTS history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_url TEXT NOT NULL,
        generated_rule TEXT,
        validation_result TEXT,
        validation_details TEXT,
        extracted_ioc TEXT,
        rule_explanation TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS cti_list (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        link TEXT NOT NULL UNIQUE,
        site_name TEXT,
        published_date DATETIME
    );

    CREATE TABLE IF NOT EXISTS bookmark_sites (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL UNIQUE,
        site_name TEXT
    );

    CREATE TABLE IF NOT EXISTS bookmark_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        site_id INTEGER REFERENCES bookmark_sites(id),
        post_url TEXT NOT NULL UNIQUE,
        post_title TEXT,
        generated_rule TEXT,
        validation_result TEXT,
        extracted_ioc TEXT,
        rule_explanation TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """
    try:
        with get_db_connection() as conn:
            conn.executescript(create_table_sql)
        print(f"INFO: Database '{DB_FILE}' initialized successfully.")
    except Exception as e:
        print(f"ERROR: Failed to initialize database - {e}")

# --- 1. History (수동 분석) 기능 ---

def add_history_record(result: Dict[str, Any]):
    """Home 페이지의 수동 분석 결과를 history 테이블에 저장합니다."""
    sql = """
    INSERT INTO history (
        source_url, generated_rule, validation_result, 
        validation_details, extracted_ioc, rule_explanation
    ) VALUES (?, ?, ?, ?, ?, ?)
    """
    try:
        with get_db_connection() as conn:
            conn.execute(sql, (
                result.get("source_url"),
                result.get("generated_rule"),
                result.get("validation_result"),
                result.get("validation_details"),
                json.dumps(result.get("extracted_ioc", {})), # dict -> JSON 문자열
                json.dumps(result.get("rule_explanation", {})) # dict -> JSON 문자열
            ))
        print(f"INFO: New history record added for {result.get('source_url')}")
    except Exception as e:
        print(f"ERROR: Failed to add history record - {e}")

def get_history_list(limit: int = 50) -> List[Dict[str, Any]]:
    """History 페이지에 보여줄 최근 분석 목록을 반환합니다."""
    sql = "SELECT id, source_url, generated_rule, created_at FROM history ORDER BY created_at DESC LIMIT ?"
    try:
        with get_db_connection() as conn:
            rows = conn.execute(sql, (limit,)).fetchall()
            # sqlite3.Row 객체를 딕셔너리로 변환
            return [dict(row) for row in rows]
    except Exception as e:
        print(f"ERROR: Failed to get history list - {e}")
        return []

def get_history_detail(record_id: int) -> Dict[str, Any] | None:
    """History 상세 보기 (Home 화면에서 재현)를 위한 단일 레코드 반환"""
    sql = "SELECT * FROM history WHERE id = ?"
    try:
        with get_db_connection() as conn:
            row = conn.execute(sql, (record_id,)).fetchone()
            if row:
                data = dict(row)
                # JSON 문자열을 다시 dict로 변환
                data["extracted_ioc"] = json.loads(data.get("extracted_ioc", "{}"))
                data["rule_explanation"] = json.loads(data.get("rule_explanation", "{}"))
                return data
            return None
    except Exception as e:
        print(f"ERROR: Failed to get history detail (id={record_id}) - {e}")
        return None

# --- 2. CTI List (자동 수집 알림) 기능 ---

def add_cti_post(title: str, link: str, site_name: str, published_date: datetime):
    """수집기가 발견한 새 글을 cti_list 테이블에 저장합니다."""
    sql = "INSERT OR IGNORE INTO cti_list (title, link, site_name, published_date) VALUES (?, ?, ?, ?)"
    try:
        with get_db_connection() as conn:
            conn.execute(sql, (title, link, site_name, published_date))
        # (중복 시 IGNORE되므로 로그는 생략)
    except Exception as e:
        print(f"ERROR: Failed to add CTI post - {e}")

def get_cti_list(limit: int = 100) -> List[Dict[str, Any]]:
    """CTI List 페이지에 보여줄 최신 글 목록을 반환합니다."""
    
    # --- ▼▼▼▼▼ 여기가 수정되었습니다! ('id' 추가) ▼▼▼▼▼ ---
    sql = "SELECT id, title, link, site_name, published_date FROM cti_list ORDER BY published_date DESC LIMIT ?"
    # --- ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲ ---
    
    try:
        with get_db_connection() as conn:
            rows = conn.execute(sql, (limit,)).fetchall()
            return [dict(row) for row in rows]
    except Exception as e:
        print(f"ERROR: Failed to get CTI list - {e}")
        return []

# --- 3. Bookmarked (자동 분석) 기능 ---

def add_bookmark_site(url: str, site_name: str = "") -> bool:
    """사용자가 북마크한 사이트를 DB에 추가합니다."""
    sql = "INSERT OR IGNORE INTO bookmark_sites (url, site_name) VALUES (?, ?)"
    try:
        with get_db_connection() as conn:
            cursor = conn.execute(sql, (url, site_name))
            return cursor.rowcount > 0 # 0보다 크면 새로 추가됨
    except Exception as e:
        print(f"ERROR: Failed to add bookmark site - {e}")
        return False

def get_bookmark_sites() -> List[Dict[str, Any]]:
    """수집기가 모니터링할 사이트 목록을 반환합니다."""
    sql = "SELECT id, url, site_name FROM bookmark_sites LIMIT 5" # 최대 5개
    try:
        with get_db_connection() as conn:
            rows = conn.execute(sql).fetchall()
            return [dict(row) for row in rows]
    except Exception as e:
        print(f"ERROR: Failed to get bookmark sites - {e}")
        return []

def add_bookmark_result(result: Dict[str, Any]):
    """수집기가 자동 분석한 결과를 bookmark_results 테이블에 저장합니다."""
    sql = """
    INSERT OR IGNORE INTO bookmark_results (
        post_url, post_title, generated_rule, validation_result, 
        extracted_ioc, rule_explanation, site_id
    ) VALUES (?, ?, ?, ?, ?, ?, ?)
    """
    try:
        with get_db_connection() as conn:
            conn.execute(sql, (
                result.get("post_url"),
                result.get("post_title"),
                result.get("generated_rule"),
                result.get("validation_result"),
                json.dumps(result.get("extracted_ioc", {})),
                json.dumps(result.get("rule_explanation", {})),
                result.get("site_id") # bookmark_sites 테이블의 ID
            ))
        print(f"INFO: New bookmark result added for {result.get('post_url')}")
    except Exception as e:
        print(f"ERROR: Failed to add bookmark result - {e}")

def get_bookmark_results_list(limit: int = 10) -> List[Dict[str, Any]]:
    """Bookmarked Pages에 보여줄 최신 자동 분석 결과를 반환합니다."""
    sql = "SELECT id, post_url, post_title, generated_rule, created_at FROM bookmark_results ORDER BY created_at DESC LIMIT ?"
    try:
        with get_db_connection() as conn:
            rows = conn.execute(sql, (limit,)).fetchall()
            return [dict(row) for row in rows]
    except Exception as e:
        print(f"ERROR: Failed to get bookmark results list - {e}")
        return []

def get_bookmark_result_detail(record_id: int) -> Dict[str, Any] | None:
    """북마크 상세 보기 (Home 화면 재현용)를 위한 단일 레코드 반환"""
    sql = "SELECT * FROM bookmark_results WHERE id = ?"
    try:
        with get_db_connection() as conn:
            row = conn.execute(sql, (record_id,)).fetchone()
            if row:
                data = dict(row)
                # source_url 필드를 추가 (RuleResponse 스키마와 맞추기 위해)
                data["source_url"] = data.get("post_url") 
                data["extracted_ioc"] = json.loads(data.get("extracted_ioc", "{}"))
                data["rule_explanation"] = json.loads(data.get("rule_explanation", "{}"))
                return data
            return None
    except Exception as e:
        print(f"ERROR: Failed to get bookmark detail (id={record_id}) - {e}")
        return None
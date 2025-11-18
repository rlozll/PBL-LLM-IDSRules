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
        url TEXT NOT NULL,
        site_name TEXT,
        link_id INTEGER NOT NULL UNIQUE -- <-- [수정됨] link_id 컬럼 추가
    );

    CREATE TABLE IF NOT EXISTS bookmark_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        site_id INTEGER REFERENCES bookmark_sites(id),
        post_url TEXT NOT NULL UNIQUE,
        post_title TEXT,
        generated_rule TEXT,
        validation_result TEXT,
        validation_details TEXT,
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
                json.dumps(result.get("extracted_ioc", {})),
                json.dumps(result.get("rule_explanation", {}))
            ))
        print(f"INFO: New history record added for {result.get('source_url')}")
    except Exception as e:
        print(f"ERROR: Failed to add history record - {e}")

def get_history_list(limit: int = 100) -> List[Dict[str, Any]]:
    """History 페이지에 보여줄 최근 분석 목록을 반환합니다."""
    sql = "SELECT id, source_url, generated_rule, created_at FROM history ORDER BY created_at DESC LIMIT ?"
    try:
        with get_db_connection() as conn:
            rows = conn.execute(sql, (limit,)).fetchall()
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
    except Exception as e:
        print(f"ERROR: Failed to add CTI post - {e}")

def get_cti_list(limit: int = 100) -> List[Dict[str, Any]]:
    """CTI List 페이지에 보여줄 최신 글 목록을 반환합니다."""
    sql = "SELECT id, title, link, site_name, published_date FROM cti_list ORDER BY published_date DESC LIMIT ?"
    try:
        with get_db_connection() as conn:
            rows = conn.execute(sql, (limit,)).fetchall()
            return [dict(row) for row in rows]
    except Exception as e:
        print(f"ERROR: Failed to get CTI list - {e}")
        return []

# --- 3. Bookmarked (자동 분석) 기능 (수정됨) ---

def add_bookmark_site(url: str, site_name: str, link_id: int) -> bool:
    """사용자가 북마크한 사이트를 DB에 추가(또는 수정)합니다."""
    # link_id가 이미 존재하는지 확인 (예: Link 1 버튼을 두 번 누름)
    # 이미 존재하면 URL만 업데이트
    sql_update = "UPDATE bookmark_sites SET url = ?, site_name = ? WHERE link_id = ?"
    sql_insert = "INSERT OR IGNORE INTO bookmark_sites (url, site_name, link_id) VALUES (?, ?, ?)"
    
    try:
        with get_db_connection() as conn:
            # 먼저 업데이트 시도
            cursor = conn.execute(sql_update, (url, site_name, link_id))
            if cursor.rowcount > 0:
                print(f"INFO: Bookmark {link_id} updated.")
                return True # 기존 링크 업데이트 성공
            
            # 업데이트 대상이 없으면 새로 삽입
            cursor = conn.execute(sql_insert, (url, site_name, link_id))
            if cursor.rowcount > 0:
                print(f"INFO: Bookmark {link_id} added.")
                return True # 새로 추가 성공
            
            # 혹시 모를 UNIQUE 제약조건 실패 (예: 다른 link_id에 같은 URL)
            # 이 경우, 이미 존재하는 URL을 수정하려고 한 것일 수 있으므로
            # url 기준으로 link_id를 업데이트 시도
            sql_update_by_url = "UPDATE bookmark_sites SET link_id = ?, site_name = ? WHERE url = ?"
            cursor = conn.execute(sql_update_by_url, (link_id, site_name, url))
            if cursor.rowcount > 0:
                 print(f"INFO: Bookmark {link_id} updated by URL.")
                 return True

            return False # 모든 시도 실패

    except Exception as e:
        print(f"ERROR: Failed to add/update bookmark site - {e}")
        return False

def get_bookmark_sites() -> List[Dict[str, Any]]:
    """수집기가 모니터링할 사이트 목록을 반환합니다."""
    sql = "SELECT id, url, site_name, link_id FROM bookmark_sites ORDER BY link_id ASC LIMIT 5"
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
        site_id, post_url, post_title, generated_rule, 
        validation_result, validation_details, extracted_ioc, rule_explanation
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """
    try:
        with get_db_connection() as conn:
            conn.execute(sql, (
                result.get("site_id"),
                result.get("post_url"),
                result.get("post_title"),
                result.get("generated_rule"),
                result.get("validation_result"),
                result.get("validation_details"),
                json.dumps(result.get("extracted_ioc", {})),
                json.dumps(result.get("rule_explanation", {}))
            ))
        print(f"INFO: New bookmark result added for {result.get('post_url')}")
    except Exception as e:
        print(f"ERROR: Failed to add bookmark result - {e}")

def get_bookmark_results_list(limit: int = 20) -> List[Dict[str, Any]]:
    """Bookmarked Pages에 보여줄 최신 자동 분석 결과를 반환합니다."""
    sql = """
    SELECT br.id, br.post_url, br.post_title, br.generated_rule, br.created_at, bs.link_id, bs.site_name
    FROM bookmark_results br
    LEFT JOIN bookmark_sites bs ON br.site_id = bs.id
    ORDER BY br.created_at DESC
    LIMIT ?
    """
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
                data["source_url"] = data.get("post_url") # Home 화면과 키 이름 맞추기
                data["extracted_ioc"] = json.loads(data.get("extracted_ioc", "{}"))
                data["rule_explanation"] = json.loads(data.get("rule_explanation", "{}"))
                return data
            return None
    except Exception as e:
        print(f"ERROR: Failed to get bookmark detail (id={record_id}) - {e}")
        return None
    
def delete_bookmark_result(result_id: int) -> bool:
    """bookmark_results 테이블에서 특정 ID를 삭제"""
    sql = "DELETE FROM bookmark_results WHERE id = ?"
    try:
        with get_db_connection() as conn:
            cursor = conn.execute(sql, (result_id,))
            return cursor.rowcount > 0
    except Exception as e:
        print(f"ERROR: Failed to delete bookmark result (id={result_id}) - {e}")
        return False

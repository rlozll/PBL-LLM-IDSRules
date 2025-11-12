# /app.py

import os
import sys
import uvicorn
# ▼▼▼ 인증 관련 모듈 임포트 ▼▼▼
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from dotenv import load_dotenv
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any # <- List, Dict, Any 임포트

# 내부 모듈
from core.parser import get_text_from_url
from core.llm_handler import generate_analysis_from_text
from utils.validator import validate_rule # <- validate_rule을 정확히 임포트
from core.vt_client import vt_fetch_url_report
from fastapi.middleware.cors import CORSMiddleware
import utils.db as db # <- DB 모듈 임포트

from apscheduler.schedulers.background import BackgroundScheduler
from scripts.rss_collector import collect_all_sources # rss_collector.py의 함수 임포트

# ──────────────────────────────────────────────────────────────────────────────
# 0) 환경 로드 및 인증 설정
# ──────────────────────────────────────────────────────────────────────────────
load_dotenv()
db.init_db() # <-- 서버 시작 시 DB 테이블 자동 생성

# --- .env 값 로드 ---
DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "default_super_secret_key_please_change")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "480"))

if not os.getenv("GOOGLE_API_KEY"):
    print("WARNING: GOOGLE_API_KEY not set.")
if not DASHBOARD_PASSWORD:
    print("FATAL WARNING: DASHBOARD_PASSWORD not set.")

# --- OAuth2 설정 ---
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")

# ──────────────────────────────────────────────────────────────────────────────
# 1) FastAPI 앱
# ──────────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="CTI-Rule-Generator API",
    description="CTI 문서를 분석하여 IDS Rule을 자동 생성하는 시스템의 API입니다.",
    version="1.3.0",
)

# --- CORS 설정 ---
origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ──────────────────────────────────────────────────────────────────────────────
# 2) 스키마
# ──────────────────────────────────────────────────────────────────────────────
class RuleRequest(BaseModel):
    url: str

class RuleResponse(BaseModel):
    id: int | None = None
    source_url: str
    extracted_ioc: dict
    generated_rule: str
    validation_result: str
    validation_details: str | None = None
    rule_explanation: dict | str
    vt_summary: dict | None = None

class Token(BaseModel):
    access_token: str
    token_type: str

class HistoryListItem(BaseModel):
    id: int
    source_url: str
    generated_rule: str
    created_at: datetime

class CtiListItem(BaseModel):
    id: int
    title: str
    link: str
    site_name: str
    published_date: datetime | None

class BookmarkSite(BaseModel):
    id: int | None = None
    url: str
    site_name: str | None = None

class BookmarkResultItem(BaseModel):
    id: int
    post_url: str
    post_title: str
    generated_rule: str
    created_at: datetime

# ──────────────────────────────────────────────────────────────────────────────
# 3) 유틸: Snort 룰 1차 형태검사
# ──────────────────────────────────────────────────────────────────────────────
def _is_probably_snort_rule(s: str) -> bool:
    # (기존 코드와 동일)
    import re
    if not s or s.lower().startswith("error:"): return False
    lines = [L.strip() for L in s.strip().splitlines() if L.strip()]
    if not lines: return False
    pat = re.compile(r'^alert\s+\w+\s+.*?\s+->\s+.*?\s+\(.*?\s*msg:"[^"]+";.*?\s*sid:\d+;.*?\s*rev:\d+;.*?\)\s*$', re.I | re.S)
    return all(pat.search(L) for L in lines)

# ──────────────────────────────────────────────────────────────────────────────
# 4) 인증 함수
# ──────────────────────────────────────────────────────────────────────────────
def authenticate_user(password: str):
    # (기존 코드와 동일)
    if password and password == DASHBOARD_PASSWORD: return True
    return False

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    # (기존 코드와 동일)
    to_encode = data.copy()
    if expires_delta: expire = datetime.now(timezone.utc) + expires_delta
    else: expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    # (기존 코드와 동일)
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        expire_timestamp = payload.get("exp")
        if expire_timestamp is None or datetime.now(timezone.utc) > datetime.fromtimestamp(expire_timestamp, tz=timezone.utc):
             raise credentials_exception
        return True
    except JWTError:
        raise credentials_exception

# ──────────────────────────────────────────────────────────────────────────────
# 5) 엔드포인트
# ──────────────────────────────────────────────────────────────────────────────

# --- 로그인 ---
@app.post("/api/login", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user_authenticated = authenticate_user(form_data.password)
    if not user_authenticated:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password",
            # --- ▼▼▼▼▼ 여기가 수정되었습니다! (불필요한 ... 제거) ▼▼▼▼▼ ---
            headers={"WWW-Authenticate": "Bearer"}
            # --- ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲ ---
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": "dashboard_user"}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

# --- Home: 수동 분석 및 History 저장 ---
@app.post(
    "/api/generate-rule",
    response_model=RuleResponse,
    summary="CTI URL로부터 IDS Rule 생성",
    dependencies=[Depends(get_current_user)]
)
async def create_rule_from_url(request: RuleRequest):
    # (기존 코드와 동일)
    print(f"INFO: URL 수신: {request.url}")

    # 1. 파싱
    try:
        parsed_text = get_text_from_url(request.url)
        if not parsed_text or len(parsed_text) < 50: raise ValueError(f"파싱된 텍스트가 너무 짧습니다 ({len(parsed_text)}자).")
        print(f"INFO: 텍스트 파싱 성공 (글자 수: {len(parsed_text)})")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"URL에서 텍스트를 파싱하는 데 실패했습니다: {e}")

    # 2. LLM 호출
    text_for_llm = parsed_text
    print("INFO: LLM 분석용 텍스트 준비 완료 (전체 본문 사용)")
    try:
        llm_output = await generate_analysis_from_text(text_for_llm)
    except Exception as e:
         raise HTTPException(status_code=500, detail={"stage": "llm", "error": "Handler Exception", "detail": str(e)})

    if llm_output.get("error"):
        stage = "ioc" if "IOC" in llm_output["error"] else "rule" if "RULE" in llm_output["error"] else "llm"
        print(f"ERROR: LLM 처리 실패 - {llm_output['error']}")
        raise HTTPException(status_code=502, detail={"stage": stage, "error": llm_output["error"], "detail": llm_output.get("explanation", "")})

    extracted_ioc = llm_output.get("ioc", {})
    rule_to_validate = (llm_output.get("rule") or "").strip()
    explanation = llm_output.get("explanation", "설명 없음.")

    if not rule_to_validate:
        raise HTTPException(status_code=500, detail="LLM이 유효한 Rule을 생성하지 못했습니다.")
    if not _is_probably_snort_rule(rule_to_validate):
        raise HTTPException(status_code=400, detail={"stage": "validate", "error": "precheck failed", "rule": rule_to_validate[:300]})

    # 4. 통합 검증
    validation_status = "Skipped"
    validation_details = ""
    try:
        if sys.platform == "darwin":
            validation_status = "Skipped on macOS"
        else:
            validation_result_dict = validate_rule(rule_to_validate) # (engine= 인자 없이 호출)
            validation_status = validation_result_dict["overall_status"]
            
            if validation_status == "Failed":
                 validation_details = f"Syntax Error Detail:\n{validation_result_dict['syntax_check_output']}"
            elif validation_status == "Warning":
                 warnings_text = "\n".join([f"- {w}" for w in validation_result_dict["static_warnings"]])
                 validation_details = f"Static Analysis Warnings:\n{warnings_text}"
            else:
                 validation_details = "Syntax OK. No static warnings found."
    except Exception as e:
        print(f"ERROR: validator 모듈 실행 중 충돌 - {e}")
        validation_status = "ValidatorError"; validation_details = str(e)

    print(f"INFO: Rule 검증 결과: {validation_status}")
    if validation_details: print(f"INFO: 검증 상세:\n{validation_details}")

    # 5. VirusTotal
    vt_summary = None # (기존 로직 동일 - 생략)
    
    # 6. 최종 응답 객체 생성
    response_data = RuleResponse(
        source_url=request.url,
        extracted_ioc=extracted_ioc,
        generated_rule=rule_to_validate,
        validation_result=validation_status,
        validation_details=validation_details,
        rule_explanation=explanation,
        vt_summary=vt_summary,
    )
    
    # 7. DB에 History 저장
    if validation_status != "Failed" and validation_status != "ValidatorError":
        try:
            db.add_history_record(response_data.model_dump())
        except Exception as e:
            print(f"ERROR: History DB 저장 실패 - {e}")

    return response_data

# --- History: 목록 조회 ---
@app.get("/api/history", response_model=List[HistoryListItem], dependencies=[Depends(get_current_user)])
async def get_history():
    """History 탭의 목록을 반환합니다."""
    return db.get_history_list()

# --- History: 상세 조회 ---
@app.get("/api/history/{record_id}", response_model=RuleResponse, dependencies=[Depends(get_current_user)])
async def get_history_detail_by_id(record_id: int):
    """History 상세 보기 (Home 화면 재현용)"""
    record = db.get_history_detail(record_id)
    if not record:
        raise HTTPException(status_code=404, detail="History record not found")
    return RuleResponse(**record)

# --- CTI Lists: 목록 조회 ---
@app.get("/api/new_cti_list", response_model=List[CtiListItem], dependencies=[Depends(get_current_user)])
async def get_cti_list():
    """CTI List 탭의 목록을 반환합니다."""
    return db.get_cti_list()

# --- Bookmarks: 목록 조회 (임시 Stub) ---
@app.get("/api/bookmarks", response_model=List[BookmarkResultItem], dependencies=[Depends(get_current_user)])
async def get_bookmark_results():
    """Bookmarked Pages 탭의 자동 분석 결과 목록을 반환합니다."""
    # (utils/db.py에 구현 필요)
    print("WARNING: /api/bookmarks가 아직 구현되지 않았습니다. 임시 데이터를 반환합니다.")
    return [
        BookmarkResultItem(id=1, post_url="https://example.com/bookmark-post", post_title="임시 북마크 분석 결과", generated_rule="alert tcp ...", created_at=datetime.now())
    ]

scheduler = BackgroundScheduler(daemon=True)

@app.on_event("startup")
def start_scheduler():
    """
    FastAPI 앱이 시작될 때 스케줄러를 함께 시작합니다.
    """
    try:
        # 1. 앱 시작 시 CTI List 1회 즉시 실행
        scheduler.add_job(collect_all_sources, 'date', run_date=datetime.now() + timedelta(seconds=5)) 
        
        # 2. 이후 1시간(3600초)마다 반복 실행
        scheduler.add_job(collect_all_sources, 'interval', seconds=3600)
        
        # (필요시 북마크 수집기 작업도 여기에 추가)
        
        scheduler.start()
        print("INFO: Background scheduler started. CTI List collection scheduled.")
    except Exception as e:
        print(f"ERROR: Failed to start scheduler - {e}")

@app.on_event("shutdown")
def shutdown_scheduler():
    """FastAPI 앱이 종료될 때 스케줄러도 함께 종료합니다."""
    scheduler.shutdown()
    print("INFO: Background scheduler shut down.")


# ──────────────────────────────────────────────────────────────────────────────
# 6) 실행
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("INFO: CTI-Rule-Generator API 서버를 시작합니다.")
    print("INFO: http://127.0.0.1:8000/docs 로 접속하세요.")
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
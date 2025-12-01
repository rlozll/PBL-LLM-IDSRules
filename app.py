# /app.py

import os
import sys
import uvicorn
import json # (db.py에서 json을 사용하므로, 여기서는 직접 필요하지 않을 수 있음)

# --- FastAPI 및 인증/보안 모듈 ---
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from dotenv import load_dotenv
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any
from fastapi.responses import JSONResponse
import httpx
from bs4 import BeautifulSoup
from pydantic import BaseModel
from typing import List, Optional, Any
from pydantic import BaseModel

# --- 백그라운드 작업(수집기) 모듈 ---
from apscheduler.schedulers.background import BackgroundScheduler
from scripts.rss_collector import collect_all_sources
# (북마크 자동 분석 스크립트 - 나중에 구현 시 주석 해제)
from scripts.bookmark_processor import process_bookmarks

# --- 내부 핵심 모듈 ---
from core.parser import get_text_from_url
from core.llm_handler import generate_analysis_from_text
from utils.validator import validate_rule # 통합 검증 함수
from core.vt_client import vt_fetch_url_report
from fastapi.middleware.cors import CORSMiddleware
import utils.db as db # DB 유틸리티 모듈

# ──────────────────────────────────────────────────────────────────────────────
# 0) 환경 로드 및 DB/인증 설정
# ──────────────────────────────────────────────────────────────────────────────
load_dotenv()
db.init_db() # <-- 서버 시작 시 DB 테이블 자동 생성 및 확인

# --- .env 값 로드 ---
DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "default_super_secret_key_please_change")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "480")) # 8시간

# --- 환경 변수 경고 ---
if not os.getenv("GOOGLE_API_KEY"):
    print("WARNING: GOOGLE_API_KEY가 .env 파일에 설정되지 않았습니다.")
if not DASHBOARD_PASSWORD:
    print("FATAL WARNING: DASHBOARD_PASSWORD가 .env 파일에 설정되지 않았습니다! 로그인이 실패합니다.")

# --- OAuth2 설정 ---
# /api/login 엔드포인트를 토큰 URL로 사용
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")

# ──────────────────────────────────────────────────────────────────────────────
# 1) FastAPI 앱 생성 및 미들웨어 설정
# ──────────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="CTI-Rule-Generator API",
    description="CTI 문서를 분석하여 IDS Rule을 자동 생성하는 시스템의 API입니다.",
    version="1.3.1", # DB 연동 및 오류 수정 완료
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
# 2) Pydantic 스키마 (API 입출력 모델)
# ──────────────────────────────────────────────────────────────────────────────

# --- Home (수동 분석) ---
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

# --- 인증 ---
class Token(BaseModel):
    access_token: str
    token_type: str

# --- History ---
class HistoryListItem(BaseModel):
    id: int
    source_url: str
    page_title: str | None = None
    generated_rule: str
    created_at: datetime

# --- CTI Lists ---
class CtiListItem(BaseModel):
    id: int
    title: str
    link: str
    site_name: str
    published_date: datetime | None

# --- Bookmarks ---
class BookmarkSite(BaseModel): # DB 모델과 일치
    id: int
    url: str
    site_name: str | None = None
    link_id: int

class BookmarkSiteRequest(BaseModel): # 프론트엔드 요청용
    url: str
    site_name: str | None = None
    link_id: int 

class BookmarkResultItem(BaseModel): # 피드 목록용
    id: int
    post_url: str
    post_title: str
    generated_rule: str
    created_at: datetime
    link_id: int | None = None 
    site_name: str | None = None

class HistoryResponse(BaseModel):
    id: int
    url: str
    page_title: str | None = None
    sources: List[str] = []
    generated_rule: str
    explanation: Any  # 기존 analysis['explanation'] 구조 그대로
    created_at: Optional[str] = None  # DB에 저장되는 생성일

class HistoryCreate(BaseModel):
    url: str  # 클라이언트에서 전송할 URL

# ──────────────────────────────────────────────────────────────────────────────
# 3) 유틸: Snort 룰 1차 형태검사
# ──────────────────────────────────────────────────────────────────────────────
def _is_probably_snort_rule(s: str) -> bool:
    """LLM이 생성한 텍스트가 Snort Rule의 최소 형태를 갖췄는지 빠르게 검사"""
    import re
    if not s or s.lower().startswith("error:"): return False
    lines = [L.strip() for L in s.strip().splitlines() if L.strip()]
    if not lines: return False
    # Snort 2 규칙 패턴 (간단 버전)
    pat = re.compile(r'^alert\s+\w+\s+.*?\s+->\s+.*?\s+\(.*?\s*msg:"[^"]+";.*?\s*sid:\d+;.*?\s*rev:\d+;.*?\)\s*$', re.I | re.S)
    return all(pat.search(L) for L in lines)

# ──────────────────────────────────────────────────────────────────────────────
# 4) 인증 함수
# ──────────────────────────────────────────────────────────────────────────────
def authenticate_user(password: str):
    """간단히 .env 파일의 비밀번호와 일치하는지 확인"""
    if password and password == DASHBOARD_PASSWORD: 
        return True
    return False

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    """JWT 토큰 생성"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    """토큰을 검증하고, 유효하면 True를 반환합니다."""
    # (오류 수정됨)
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        expire_timestamp = payload.get("exp")
        if expire_timestamp is None or datetime.now(timezone.utc) > datetime.fromtimestamp(expire_timestamp, tz=timezone.utc):
             raise credentials_exception # 만료됨
        return True # 인증 성공
    except JWTError:
        raise credentials_exception

# ──────────────────────────────────────────────────────────────────────────────
# 5) 엔드포인트
# ──────────────────────────────────────────────────────────────────────────────

# --- 로그인 ---
@app.post("/api/login", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """프론트엔드로부터 폼 데이터를 받아 로그인을 처리하고 토큰을 발급합니다."""
    user_authenticated = authenticate_user(form_data.password)
    if not user_authenticated:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password",
            headers={"WWW-Authenticate": "Bearer"} # (오류 수정됨)
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": "dashboard_user"}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

# --- Home: 수동 분석 및 History 저장 ---
@app.post(
    "/api/generate-rule",
    response_model=RuleResponse,
    summary="CTI URL로부터 IDS Rule 생성",
    dependencies=[Depends(get_current_user)]  # 인증 필수
)
async def create_rule_from_url(request: RuleRequest):
    """단일 URL을 받아 파싱, LLM 분석, 검증을 수행하고 History DB에 저장합니다."""
    print(f"INFO: URL 수신: {request.url}")
    page_title = request.url

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(request.url)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")
                title_tag = soup.find("title")
                if title_tag and title_tag.text.strip():
                    page_title = title_tag.text.strip()
    except Exception as e:
        print(f"페이지 제목 추출 실패: {e}")
    
    # 1. 파싱
    try:
        parsed_text = get_text_from_url(request.url)
        if not parsed_text or len(parsed_text) < 50: 
            raise ValueError(f"파싱된 텍스트가 너무 짧습니다 ({len(parsed_text)}자).")
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

    rule_to_validate = (llm_output.get("rule") or "").strip()
    extracted_ioc = llm_output.get("ioc", {})
    explanation = llm_output.get("explanation", {})

    if not rule_to_validate:
        raise HTTPException(status_code=500, detail="LLM이 유효한 Rule을 생성하지 못했습니다.")
    if not _is_probably_snort_rule(rule_to_validate):
        raise HTTPException(status_code=400, detail={"stage": "validate", "error": "precheck failed", "rule": rule_to_validate[:300]})

    # 3. Validator 실행
    validation_status = "Skipped"
    validation_details = ""
    try:
        if sys.platform != "darwin":
            val_result = validate_rule(rule_to_validate)
            validation_status = val_result.get("overall_status", "Unknown")
            if validation_status == "Failed":
                validation_details = f"Syntax Error Detail:\n{val_result.get('syntax_check_output','')}"
            elif validation_status == "Warning":
                warnings_text = "\n".join([f"- {w}" for w in val_result.get("static_warnings", [])])
                validation_details = f"Static Analysis Warnings:\n{warnings_text}"
            else:
                validation_details = "Syntax OK. No static warnings"
    except Exception as e:
        validation_status = "ValidatorError"
        validation_details = str(e)
        print(f"ERROR: validator 모듈 실행 중 충돌 - {e}")

    print(f"INFO: Rule 검증 결과: {validation_status}")
    if validation_details: print(f"INFO: 검증 상세:\n{validation_details}")

    # 4. VirusTotal 조회
    vt_summary = None
    try:
        if os.getenv("VT_API_KEY"):
            vt_summary = vt_fetch_url_report(request.url)
            print("INFO: VirusTotal 정보 조회 성공")
        else:
            print("INFO: VT_API_KEY 미설정 → VirusTotal 스킵")
            vt_summary = {"status": "skipped", "detail": "VT_API_KEY not configured"}
    except Exception as e:
        print(f"ERROR: VirusTotal 조회 중 오류 - {e}")
        vt_summary = {"status": "error", "detail": str(e)}

    # 5. DB에 History 저장
    if validation_status not in ["Failed", "ValidatorError"]:
        try:
            db.add_history_record({
                "source_url": request.url,
                "page_title": page_title,
                "generated_rule": rule_to_validate,
                "validation_result": validation_status,
                "validation_details": validation_details,
                "extracted_ioc": extracted_ioc,
                "rule_explanation": explanation
            })
        except Exception as e:
            print(f"ERROR: History DB 저장 실패 - {e}")

    # 6. 최종 응답 반환
    return RuleResponse(
        source_url=request.url,
        extracted_ioc=extracted_ioc,
        generated_rule=rule_to_validate,
        validation_result=validation_status,
        validation_details=validation_details,
        rule_explanation=explanation,
        vt_summary=vt_summary
    )


# --- History: 목록 조회 ---
@app.get("/api/history", response_model=List[HistoryListItem], dependencies=[Depends(get_current_user)])
async def get_history():
    return db.get_history_list()

# --- History: 상세 조회 ---
@app.get("/api/history/{record_id}", response_model=RuleResponse, dependencies=[Depends(get_current_user)])
async def get_history_detail_by_id(record_id: int):
    record = db.get_history_detail(record_id)
    if not record:
        raise HTTPException(status_code=404, detail="History record not found")
    return RuleResponse(**record)

@app.post("/api/history", response_model=HistoryResponse, dependencies=[Depends(get_current_user)])
async def create_history(record: HistoryCreate):
    url = record.url
    page_title = "제목 없음"

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, timeout=5)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")
                title_tag = soup.find("title")
                if title_tag and title_tag.text.strip():
                    page_title = title_tag.text.strip()
    except Exception as e:
        print(f"페이지 제목 추출 실패: {e}")

    # LLM 분석
    analysis = await generate_analysis_from_text(url)
    rule_to_validate = (analysis.get("rule") or "").strip()
    extracted_ioc = analysis.get("ioc", {})
    explanation = analysis.get("explanation", {})

    # Validator 실행
    validation_status = "Skipped"
    validation_details = ""
    try:
        if sys.platform != "darwin":
            val_result = validate_rule(rule_to_validate)
            validation_status = val_result.get("overall_status", "Unknown")
            if validation_status == "Failed":
                validation_details = f"Syntax Error Detail:\n{val_result.get('syntax_check_output','')}"
            elif validation_status == "Warning":
                validation_details = "\n".join([f"- {w}" for w in val_result.get("static_warnings", [])])
            else:
                validation_details = "Syntax OK. No static warnings"
    except Exception as e:
        validation_status = "ValidatorError"
        validation_details = str(e)

    # DB에 맞게 구조 생성
    db_payload = {
        "source_url": url,
        "page_title": page_title,
        "generated_rule": rule_to_validate,
        "validation_result": validation_status,
        "validation_details": validation_details,
        "extracted_ioc": extracted_ioc,
        "rule_explanation": explanation
    }

    # 저장 함수 호출
    #db.add_history_record(db_payload)
    new_record_id = db.add_history_record(db_payload)

    # 프론트에 반환
    return HistoryResponse(
        id = new_record_id,
        url=url,
        title=page_title,
        sources=[url],
        generated_rule=rule_to_validate,
        validation_result=validation_status,
        validation_details=validation_details,
        extracted_ioc=extracted_ioc,
        rule_explanation=explanation,
        vt_summary=None
    )

# --- CTI Lists: 목록 조회 ---
@app.get("/api/new_cti_list", response_model=List[CtiListItem], dependencies=[Depends(get_current_user)])
async def get_cti_list():
    return db.get_cti_list()

# --- Bookmarks: 등록된 사이트 *목록* 조회 ---
@app.get("/api/bookmark-sites", response_model=List[BookmarkSite], dependencies=[Depends(get_current_user)])
async def get_sites():
    return db.get_bookmark_sites()

# --- Bookmarks: 새 사이트 *등록/수정* ---
@app.post("/api/bookmark-sites", dependencies=[Depends(get_current_user)])
async def add_site(request: BookmarkSiteRequest):
    success = db.add_bookmark_site(request.url, request.site_name or "", request.link_id)
    if success:
        return {"status": "success"}
    raise HTTPException(status_code=400, detail="Failed to add/update bookmark")

# --- Bookmarks: 자동 분석된 *결과* 목록 조회 ---
@app.get("/api/bookmark-results", response_model=List[BookmarkResultItem], dependencies=[Depends(get_current_user)])
async def get_results():
    return db.get_bookmark_results_list()

# --- Bookmarks: 자동 분석된 *결과* 상세 조회 ---
@app.get("/api/bookmark-results/{record_id}", response_model=RuleResponse, dependencies=[Depends(get_current_user)])
async def get_result_detail(record_id: int):
    record = db.get_bookmark_result_detail(record_id)
    if not record:
        raise HTTPException(status_code=404, detail="Bookmark result not found") # (오류 수정됨)
    return RuleResponse(**record)

# --- Bookmark Result 삭제 ---
@app.delete("/api/bookmark-results/{record_id}")
async def delete_bookmark_result(record_id: int, user=Depends(get_current_user)):
    try:
        deleted = db.delete_bookmark_result(record_id)  # DB 함수 호출
        if not deleted:
            raise HTTPException(status_code=404, detail="Record not found")

        return {"status": "success", "detail": "Deleted successfully"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Delete failed: {e}")

# ──────────────────────────────────────────────────────────────────────────────
# 6) 스케줄러 (앱 시작 시 자동 실행)
# ──────────────────────────────────────────────────────────────────────────────
scheduler = BackgroundScheduler(daemon=True)

@app.on_event("startup")
def start_scheduler():
    try:
        # 1. CTI List 수집 (1시간마다)
        scheduler.add_job(collect_all_sources, 'interval', seconds=3600, id="rss_collector_job", replace_existing=True)
        # (앱 시작 5초 후 1회 즉시 실행)
        scheduler.add_job(collect_all_sources, 'date', run_date=datetime.now(timezone.utc) + timedelta(seconds=5)) 
        
        # ▼▼▼▼▼ 주석 해제됨! (북마크 자동 분석 시작) ▼▼▼▼▼
        
        # 2. 북마크 자동 분석 (30분마다 반복)
        scheduler.add_job(process_bookmarks, 'interval', seconds=1800, id="bookmark_processor_job", replace_existing=True)
        
        # (테스트용: 앱 켜자마자 10초 뒤에 즉시 1회 실행)
        scheduler.add_job(process_bookmarks, 'date', run_date=datetime.now(timezone.utc) + timedelta(seconds=10))
        
        scheduler.start()
        print("INFO: Background scheduler started. CTI List & Bookmark analysis scheduled.")
    except Exception as e:
        print(f"ERROR: Failed to start scheduler - {e}")

@app.on_event("shutdown")
def shutdown_scheduler():
    scheduler.shutdown()
    print("INFO: Background scheduler shut down.")

# ──────────────────────────────────────────────────────────────────────────────
# 7) 실행
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("INFO: CTI-Rule-Generator API 서버를 시작합니다.")
    print("INFO: http://127.0.0.1:8000/docs 로 접속하세요.")
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
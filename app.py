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
# ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲

# 내부 모듈
from core.parser import get_text_from_url
from core.llm_handler import generate_analysis_from_text
from utils.validator import validate_rule # validate_rule 임포트 확인
from core.vt_client import vt_fetch_url_report
from fastapi.middleware.cors import CORSMiddleware

# ──────────────────────────────────────────────────────────────────────────────
# 0) 환경 로드 및 인증 설정
# ──────────────────────────────────────────────────────────────────────────────
load_dotenv()

# --- .env 값 로드 ---
DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD")
# .env에 JWT_SECRET_KEY가 없으면 임시 키 사용 (보안을 위해 .env에 설정 권장)
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "default_super_secret_key_please_change")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "480")) # 8시간

if not os.getenv("GOOGLE_API_KEY"):
    print("WARNING: GOOGLE_API_KEY not set. Set it in .env for AI Studio/Gemini API.")
if not DASHBOARD_PASSWORD:
    print("FATAL WARNING: DASHBOARD_PASSWORD not set in .env! Login will fail.")

# --- OAuth2 설정 ---
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login") # 로그인 경로 지정

# ──────────────────────────────────────────────────────────────────────────────
# 1) FastAPI 앱
# ──────────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="CTI-Rule-Generator API",
    description="CTI 문서를 분석하여 IDS Rule을 자동 생성하는 시스템의 API입니다.",
    version="1.2.0",
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
    source_url: str
    extracted_ioc: dict
    generated_rule: str
    validation_result: str
    validation_details: str | None = None
    rule_explanation: dict | str
    vt_summary: dict | None = None

class Token(BaseModel): # <-- 로그인 응답용 토큰 스키마
    access_token: str
    token_type: str

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
# --- ▼▼▼▼▼ 누락되었던 인증 함수들 ▼▼▼▼▼ ---
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
    """토큰을 검증하고 사용자를 반환 (여기서는 간단히 True 반환)"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        # 토큰 만료 시간 검사
        expire_timestamp = payload.get("exp")
        if expire_timestamp is None or datetime.now(timezone.utc) > datetime.fromtimestamp(expire_timestamp, tz=timezone.utc):
             raise credentials_exception # 만료됨
        return True # 인증 성공
    except JWTError:
        raise credentials_exception

# ──────────────────────────────────────────────────────────────────────────────
# 4) 엔드포인트
# ──────────────────────────────────────────────────────────────────────────────

# --- ▼▼▼▼▼ 누락되었던 로그인 엔드포인트 ▼▼▼▼▼ ---
@app.post("/api/login", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user_authenticated = authenticate_user(form_data.password)
    if not user_authenticated:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": "dashboard_user"}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.post(
    "/api/generate-rule",
    response_model=RuleResponse,
    summary="CTI URL로부터 IDS Rule 생성",
    # --- ▼▼▼ 인증 기능 활성화 ▼▼▼ ---
    dependencies=[Depends(get_current_user)]
)
async def create_rule_from_url(request: RuleRequest): # (이제 인증된 사용자만 접근 가능)
    print(f"INFO: URL 수신: {request.url}")

    # ... (1, 2, 3 단계: 파싱, LLM 호출, 사전검증 - 기존과 동일) ...
    try:
        parsed_text = get_text_from_url(request.url)
        if not parsed_text or len(parsed_text) < 50: raise ValueError("파싱된 텍스트가 너무 짧습니다.")
        print(f"INFO: 텍스트 파싱 성공 (글자 수: {len(parsed_text)})")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"URL에서 텍스트를 파싱하는 데 실패했습니다: {e}")

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

    # --- 4) 통합 검증 실행 ---
    validation_status = "Skipped"
    validation_details = ""
    try:
        if sys.platform == "darwin":
            validation_status = "Skipped on macOS"
        else:
            validation_result_dict = validate_rule(rule_to_validate)
            validation_status = validation_result_dict["overall_status"]
            
            if validation_status == "Failed":
                 validation_details = f"Syntax Error Detail:\n{validation_result_dict['syntax_check_output']}"
            elif validation_status == "Warning":
                 warnings_text = "\n".join([f"- {w}" for w in validation_result_dict["static_warnings"]])
                 validation_details = f"Static Analysis Warnings:\n{warnings_text}"
            else: # Success
                 validation_details = "Syntax OK. No static warnings found."

    except Exception as e:
        print(f"ERROR: validator 모듈 실행 중 충돌 - {e}")
        validation_status = "ValidatorError"
        validation_details = str(e)

    print(f"INFO: Rule 검증 결과: {validation_status}")
    if validation_details: print(f"INFO: 검증 상세:\n{validation_details}")

    # --- 5) VirusTotal (선택) ---
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

    # --- 6) 최종 응답 ---
    return RuleResponse(
        source_url=request.url,
        extracted_ioc=extracted_ioc,
        generated_rule=rule_to_validate,
        validation_result=validation_status,
        validation_details=validation_details,
        rule_explanation=explanation,
        vt_summary=vt_summary,
    )

# ──────────────────────────────────────────────────────────────────────────────
# (실행 부분은 기존과 동일)
# ...
if __name__ == "__main__":
    print("INFO: CTI-Rule-Generator API 서버를 시작합니다.")
    print("INFO: http://127.0.0.1:8000/docs 로 접속하세요.")
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
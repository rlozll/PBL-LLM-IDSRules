# /app.py

import os
import sys
import uvicorn
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from dotenv import load_dotenv

# 내부 모듈
<<<<<<< HEAD
from core.parser import get_text_from_url
from core.llm_handler import generate_analysis_from_text
# --- validator 임포트 수정 ---
from utils.validator import validate_rule # <- 통합 검증 함수 임포트
from core.vt_client import vt_fetch_url_report
=======
from datetime import datetime, timedelta, timezone
from core.parser import get_text_from_url               # URL → 텍스트 파싱
from core.llm_handler import generate_analysis_from_text  # LLM 호출(이미 A안으로 수정했다고 했음)
from utils.validator import validate_rule_syntax        # Snort/Suricata 검증기
from core.vt_client import vt_fetch_url_report          # VirusTotal 클라이언트
# JWT 관련 모듈
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
# CORS 미들웨어 추가 (FE<>BE 통신용)
from fastapi.middleware.cors import CORSMiddleware
>>>>>>> main

# ──────────────────────────────────────────────────────────────────────────────
# 0) 환경 로드 및 사전 점검
# ──────────────────────────────────────────────────────────────────────────────
load_dotenv()

# GOOGLE_API_KEY 사용 가정
if not os.getenv("GOOGLE_API_KEY"):
    print("WARNING: GOOGLE_API_KEY not set. Set it in .env for AI Studio/Gemini API.")

# --- JWT 관련 키 점검 ---
DASHBOARD_PASSWORD=os.getenv("DASHBOARD_PASSWORD")
JWT_SECRET_KEY=os.getenv("JWT_SECRET_KEY")
ALGORITHM=os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "480"))      # 기본 8시간


if not DASHBOARD_PASSWORD or not JWT_SECRET_KEY:
    print("FATAL ERROR: DASHBOARD_PASSWORD or JWT_SECRET_KEY not set in .env! 인증 기능을 사용할 수 없습니다.")
    # 실제 서비스에서는 여기서 종료시키는게 안전
    # sys.exit(1)
# ---


# ──────────────────────────────────────────────────────────────────────────────
# 1) FastAPI 앱
# ──────────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="CTI-Rule-Generator API",
    description="CTI 문서를 분석하여 IDS Rule을 자동 생성하는 시스템의 API입니다.",
    version="1.1.0", # 버전 업데이트 (정적 분석 추가)
)


# --- CORS 설정 추가 ---
origins=[
    "http://localhost:3000", # React 개발 서버 주소
    "http://127.0.0.1:3000",
    # 필요시 추가
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"], # 모든 HTTP 메소드 허용
    allow_headers=["*"], # 모든 헤더 허용
)

# --- 비밀번호 검증 컨텍스트 ---
# pwd_context=CryptContext(schemes=["bcrypt"], deprecated="auto") # 실제로는 해싱 비교 필요

# --- OAuth2 설정 (토큰 URL 지정) ---
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login") # 로그인 경로와 일치

# ---



# ──────────────────────────────────────────────────────────────────────────────
# 2) 스키마 (수정: validation_details 추가)
# ──────────────────────────────────────────────────────────────────────────────
class RuleRequest(BaseModel):
    url: str

class RuleResponse(BaseModel):
    source_url: str
    extracted_ioc: dict
    generated_rule: str
    validation_result: str # <- 최종 상태 (Success/Warning/Failed)
    validation_details: str # <- Snort 출력 또는 정적 분석 경고 내용
    rule_explanation: str
    vt_summary: dict | None = None


# --- 추가 ---
class Token(BaseModel): # JWT 토큰 응답용 스키마
    access_token: str
    token_type: str

# ──────────────────────────────────────────────────────────────────────────────
# 3) 유틸: Snort 룰 1차 형태검사(빠른 가드)
# ──────────────────────────────────────────────────────────────────────────────
def _is_probably_snort_rule(s: str) -> bool:
    # (기존 코드와 동일)
    import re
    if not s or s.lower().startswith("error:"): return False
    lines = [L.strip() for L in s.strip().splitlines() if L.strip()]
    if not lines: return False
    pat = re.compile(r'^alert\s+\w+\s+.*?\s+->\s+.*?\s+\(.*?\s*msg:"[^"]+";.*?\s*sid:\d+;.*?\s*rev:\d+;.*?\)\s*$', re.I | re.S)
    return all(pat.search(L) for L in lines)


# --- 인증 관련 함수 ---

# 사용자 인증 함수 (여기서는 비밀번호만 비교)
def authenticate_user(password: str):
    # 실제 비밀번호와 직접 비교
    if password==DASHBOARD_PASSWORD:
        return True
    return False

# JWT 토큰 생성 함수
def create_access_token(data: dict, expires_delta: timedelta | None=None):
    to_encode=data.copy()
    if expires_delta:
        expire=datetime.now(timezone.utc)+expires_delta
    else:
        # 기본 만료 시간
        expire=datetime.now(timezone.utc)+timedelta(minutes=15)
    to_encode.update({"exp":expire})
    encoded_jwt=jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# 현재 사용자(토큰) 확인 함수
async def get_current_user(token: str=Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # 토큰 디코딩 및 유효성 검사 (만료 시간 등)
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        # 우리 시스템은 사용자 이름이 없으므로, 유효한 토큰이기만 하면 통과
        if payload: # 간단히 페이로드가 있는지 여부만 확인
             # 만료 시간 검사 추가
             expire_timestamp = payload.get("exp")
             if expire_timestamp is None or datetime.now(timezone.utc) > datetime.fromtimestamp(expire_timestamp, tz=timezone.utc):
                 raise credentials_exception # 만료됨
             return True # 인증 성공 의미
        raise credentials_exception
    except JWTError:
        raise credentials_exception

# ---


# ──────────────────────────────────────────────────────────────────────────────
# 4) 엔드포인트 (수정: validate_rule 사용 및 결과 처리)
# ──────────────────────────────────────────────────────────────────────────────

# --- 로그인 엔드포인트 추가 ---
@app.post("/api/login", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    # OAuth2PasswordRequestForm은 username과 password 필드를 가짐
    # 우리는 username은 무시하고 password만 사용

    print(f"--- [백엔드 로그인 테스트] ---")
    print(f"1. 프론트엔드가 입력한 값: '{form_data.password}'")
    print(f"2. .env에서 읽어온 실제 비밀번호: '{DASHBOARD_PASSWORD}'")
    print(f"------------------------------")


    user_authenticated = authenticate_user(form_data.password)
    if not user_authenticated:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # 로그인 성공 시 토큰 생성
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    # 토큰 내용에는 사용자 정보 대신 간단한 식별자나 역할만 넣어도 됨
    access_token = create_access_token(
        data={"sub": "dashboard_user"}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# ---


@app.post(
    "/api/generate-rule",
    response_model=RuleResponse,
    summary="CTI URL로부터 IDS Rule 생성",
    description="입력된 URL의 CTI 문서를 파싱, LLM으로 분석하여 IDS Rule을 생성하고 검증하며, VirusTotal 정보를 추가합니다.",
)
async def create_rule_from_url(request: RuleRequest, current_user: bool=Depends(get_current_user)):
    print(f"INFO: URL 수신 (인증됨): {request.url}")

    # --- 1) 파싱 ---
    try:
        parsed_text = get_text_from_url(request.url)
        if not parsed_text or len(parsed_text) < 50: raise ValueError("파싱된 텍스트가 너무 짧습니다.")
        print(f"INFO: 텍스트 파싱 성공 (글자 수: {len(parsed_text)})")
    except Exception as e:
        print(f"ERROR: 파싱 실패 - {e}")
        raise HTTPException(status_code=400, detail=f"URL에서 텍스트를 파싱하는 데 실패했습니다: {e}")

    # --- 2) LLM 호출 ---
    text_for_llm = parsed_text
    print("INFO: LLM 분석용 텍스트 준비 완료 (전체 본문 사용)")
    try:
        llm_output = await generate_analysis_from_text(text_for_llm)
    except Exception as e:
         print(f"ERROR: LLM 핸들러 실행 중 예외 발생 - {e}")
         raise HTTPException(status_code=500, detail={"stage": "llm", "error": "Handler Exception", "detail": str(e)})

    if llm_output.get("error"):
        stage = "ioc" if "IOC" in llm_output["error"] else "rule" if "RULE" in llm_output["error"] else "llm"
        print(f"ERROR: LLM 처리 실패 - {llm_output['error']}")
        raise HTTPException(status_code=502, detail={"stage": stage, "error": llm_output["error"], "detail": llm_output.get("explanation", "")})

    extracted_ioc = llm_output.get("ioc", {})
    rule_to_validate = (llm_output.get("rule") or "").strip()
    explanation = llm_output.get("explanation", "설명 없음.")

    if not rule_to_validate:
        print("ERROR: LLM 결과에 Rule이 없음")
        raise HTTPException(status_code=500, detail="LLM이 유효한 Rule을 생성하지 못했습니다.")

    # --- 3) Snort 사전검증 ---
    if not _is_probably_snort_rule(rule_to_validate):
        print("ERROR: 사전검증 실패 - Snort 형태에 맞지 않음")
        raise HTTPException(status_code=400, detail={"stage": "validate", "error": "precheck failed", "rule": rule_to_validate[:300]})

    # --- 4) 통합 검증 실행 (수정된 부분) ---
    validation_status = "Skipped"
    validation_details = ""
    try:
        if sys.platform == "darwin":
            validation_status = "Skipped on macOS"
        else:
            # 통합 검증 함수 호출
            validation_result_dict = validate_rule(rule_to_validate)
            validation_status = validation_result_dict["overall_status"] # Success, Warning, Failed

            # 상세 결과 설정
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

    # --- 5) VirusTotal ---
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
        validation_result=validation_status, # <- 최종 상태 반영
        validation_details=validation_details, # <- 상세 내용 반영
        rule_explanation=explanation,
        vt_summary=vt_summary,
    )

# --- (추가 필요) 히스토리 엔드포인트 (인증 추가) ---
@app.get("/api/history") # 예시
async def get_rule_history(current_user: bool = Depends(get_current_user)):
    # SQLite DB에서 히스토리 읽어와 반환
    return [{"id": 1, "rule": "example rule...", "date": "..."}] # 임시

# --- (추가 필요) CTI 리스트 엔드포인트 (인증 추가) ---
@app.get("/api/new_cti_list") # 예시
async def get_latest_cti(current_user: bool = Depends(get_current_user)):
    # 알림 DB/파일 읽어와 반환
     return [{"title": "New Log4j Variant", "link": "...", "date": "..."}] # 임시

# ---

# ──────────────────────────────────────────────────────────────────────────────
# 5) 실행
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("INFO: CTI-Rule-Generator API 서버를 시작합니다.")
    print("INFO: http://127.0.0.1:8000/docs 로 접속하세요.")
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
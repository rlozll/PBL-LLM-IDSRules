# /app.py

# --- 1. 모듈 임포트 ---
import os
import sys
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv

# 사용자 정의 모듈 임포트
from core.parser import get_text_from_url               # 텍스트 파싱 모듈
from core.chunking import chunk_by_sentences            # 텍스트 청킹 모듈
from core.llm_handler import generate_analysis_from_text  # << 실제 LLM 핸들러
from utils.validator import validate_rule_syntax        # Rule 검증 모듈
from core.vt_client import vt_fetch_url_report          # VirusTotal 클라이언트 모듈

load_dotenv()

# --- 2. FastAPI 앱 생성 및 기본 설정 ---
app = FastAPI(
    title="CTI-Rule-Generator API",
    description="CTI 문서를 분석하여 IDS Rule을 자동 생성하는 시스템의 API입니다.",
    version="1.0.0", # 정식 버전으로 변경
)

# --- 3. 데이터 모델 정의 (API 입출력 형식) ---
class RuleRequest(BaseModel):
    """API가 요청받을 데이터의 형식을 정의합니다."""
    url: str

class RuleResponse(BaseModel):
    """API가 응답할 데이터의 형식을 정의합니다."""
    source_url: str
    extracted_ioc: dict
    generated_rule: str
    validation_result: str
    rule_explanation: str
    vt_summary: dict | None = None   # VirusTotal 요약 정보 추가

# --- 4. API 엔드포인트 정의 ---
@app.post("/api/generate-rule",
          response_model=RuleResponse,
          summary="CTI URL로부터 IDS Rule 생성",
          description="입력된 URL의 CTI 문서를 파싱, LLM으로 분석하여 IDS Rule을 생성하고 검증하며, VirusTotal 정보를 추가합니다.")
async def create_rule_from_url(request: RuleRequest):
    """
    전체 Rule 생성 파이프라인을 실행하는 메인 API 함수입니다.
    """
    print(f"INFO: URL 수신: {request.url}")

    # 1단계: 텍스트 파싱
    try:
        parsed_text = get_text_from_url(request.url)
        if not parsed_text or len(parsed_text) < 50:
            raise ValueError("파싱된 텍스트가 너무 짧습니다.")
        print(f"INFO: 텍스트 파싱 성공 (글자 수: {len(parsed_text)})")
    except Exception as e:
        print(f"ERROR: 파싱 실패 - {e}")
        raise HTTPException(status_code=400, detail=f"URL에서 텍스트를 파싱하는 데 실패했습니다: {e}")

    # 2단계: 텍스트 청킹 (LLM 입력용)
    # 긴 텍스트를 LLM의 토큰 제한에 맞게 문장 단위로 자릅니다.
    chunks = chunk_by_sentences(parsed_text, max_chars=4000) # 모델의 컨텍스트 길이에 맞게 조절
    text_for_llm = chunks[0] if chunks else parsed_text  # 우선 첫 번째 청크만 사용
    print(f"INFO: LLM 분석용 텍스트 준비 완료 (첫 번째 청크 사용)")

    # 3단계: LLM 분석 (실제 LLM 호출)
    try:
        llm_output = await generate_analysis_from_text(text_for_llm)
        print("INFO: 실제 LLM 처리 성공")
    except Exception as e:
        print(f"ERROR: LLM 처리 실패 - {e}")
        raise HTTPException(status_code=500, detail=f"LLM 처리 중 오류가 발생했습니다: {e}")

    # 4단계: Rule 검증
    rule_to_validate = llm_output.get("rule", "")
    if not rule_to_validate:
        print("ERROR: LLM 결과에 Rule이 포함되지 않음")
        raise HTTPException(status_code=500, detail="LLM이 유효한 Rule을 생성하지 못했습니다.")

    try:
        # macOS에서는 WSL/Snort가 없으므로 검증을 건너뜁니다.
        if sys.platform == "darwin":
            validation_status = "Skipped on macOS"
        else:
            is_valid = validate_rule_syntax(rule_to_validate, engine='snort')
            validation_status = "Success: Valid Syntax" if is_valid else "Failed: Invalid Syntax"
    except Exception as e:
        print(f"ERROR: validator 모듈 실행 중 충돌 - {e}")
        validation_status = f"ValidatorError: {e}"
    print(f"INFO: Rule 검증 결과: {validation_status}")

    # 5단계: 부가 정보 수집 (VirusTotal)
    vt_summary = None
    try:
        # VT API 키가 .env에 설정되어 있을 경우에만 호출
        if os.getenv("VT_API_KEY"):
            vt_summary = vt_fetch_url_report(request.url)
            print(f"INFO: VirusTotal 정보 조회 성공")
        else:
            print("INFO: VT_API_KEY가 설정되지 않아 VirusTotal 조회를 건너뜁니다.")
            vt_summary = {"status": "skipped", "detail": "VT_API_KEY not configured"}
    except Exception as e:
        print(f"ERROR: VirusTotal 조회 중 오류 - {e}")
        vt_summary = {"status": "error", "detail": str(e)}

    # 6단계: 최종 응답 생성
    response_data = RuleResponse(
        source_url=request.url,
        extracted_ioc=llm_output.get("ioc", {}),
        generated_rule=rule_to_validate,
        validation_result=validation_status,
        rule_explanation=llm_output.get("explanation", "설명 없음."),
        vt_summary=vt_summary
    )
    return response_data

# --- 5. 서버 실행 ---
if __name__ == "__main__":
    print("INFO: CTI-Rule-Generator API 서버를 시작합니다.")
    print("INFO: 웹 브라우저에서 http://127.0.0.1:8000/docs 로 접속하세요.")
    uvicorn.run(app, host="127.0.0.1", port=8000)
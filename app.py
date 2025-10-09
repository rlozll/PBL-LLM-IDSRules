# /app.py

# --- 1. 모듈 임포트 --- 
import os
import sys  # ← macOS 분기용
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv
from core.chunking import chunk_by_sentences 


# 사용자 정의 모듈 임포트
from core.parser import get_text_from_url
from utils.validator import validate_rule_syntax
from core.vt_client import vt_fetch_url_report  
# from core.llm_handler import generate_analysis_from_text # 최종적으로는 이 함수를 호출할 예정


load_dotenv()

# --- 2. FastAPI 앱 생성 및 기본 설정 ---
app = FastAPI(
    title="CTI-Rule-Generator API",
    description="CTI 문서를 분석하여 IDS Rule을 자동 생성하는 시스템의 API입니다.",
    version="0.1.1",
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
    vt_summary: dict | None = None   # VT 요약

# --- (임시) LLM 핸들러 함수 ---
async def placeholder_llm_handler(text: str) -> dict:
    """LLM의 응답을 흉내 내는 임시 함수입니다."""
    print("--- (임시) LLM 핸들러 호출됨 ---")
    return {
        "ioc": {"CVE": "CVE-2025-XXXX", "IP": ["1.2.3.4"]},
        "rule": "alert tcp any any -> any 80 (msg:'[LLM Generated] Fake Malware C2'; content:'/malware.exe'; classtype:trojan-activity; sid:1000002; rev:1;)",
        "explanation": "이 Rule은 '/malware.exe' 문자열을 포함하는 HTTP 트래픽을 탐지합니다. 이는 알려진 악성코드의 C2 통신 패턴입니다."
    }
# --- 임시 함수 끝 ---


# --- 4. API 엔드포인트 정의 ---
@app.post("/api/generate-rule", 
          response_model=RuleResponse, 
          summary="CTI URL로부터 IDS Rule 생성",
          description="입력된 URL의 CTI 문서를 파싱, LLM으로 분석하여 IDS Rule을 생성하고 검증합니다.")
async def create_rule_from_url(request: RuleRequest):
    """
    전체 Rule 생성 파이프라인을 실행하는 메인 API 함수입니다.
    """
    print(f"INFO: URL 수신: {request.url}")

    #  1) 텍스트 파싱
    try:
        parsed_text = get_text_from_url(request.url)
        if not parsed_text or len(parsed_text) < 50:
            raise ValueError("파싱된 텍스트가 너무 짧습니다.")
        print("INFO: 텍스트 파싱 성공")
    except Exception as e:
        print(f"ERROR: 파싱 실패 - {e}")
        raise HTTPException(status_code=400, detail=f"URL에서 텍스트를 파싱하는 데 실패했습니다: {e}")

    
    # 🔹 문장 단위 청크 (문자 기준)
    chunks = chunk_by_sentences(parsed_text, max_chars=3500, overlap_sents=1)
    text_for_llm = chunks[0] if chunks else parsed_text  # 일단 첫 청크만 사용

    # 2) LLM 처리 (임시)
    try:
        llm_output = await placeholder_llm_handler(text_for_llm)
        print("INFO: LLM 처리 성공 (임시 데이터 사용)")
    except Exception as e:
        print(f"ERROR: LLM 처리 실패 - {e}")
        raise HTTPException(status_code=500, detail=f"LLM 처리 중 오류가 발생했습니다: {e}")

    # 3) Rule 검증
    rule_to_validate = llm_output.get("rule", "")
    if not rule_to_validate:
        print("ERROR: LLM 결과에 Rule이 포함되지 않음")
        raise HTTPException(status_code=500, detail="LLM이 유효한 Rule을 생성하지 못했습니다.")

    
    
    # 👉 검증기 예외를 잡아서 500 방지 + macOS는 스킵 처리
    try:
        if sys.platform == "darwin":
            is_valid = True
            validation_status = "Skipped on macOS: validator requires WSL/Snort"
        else:
            is_valid = validate_rule_syntax(rule_to_validate, engine='snort')
            validation_status = "Success: Valid Syntax" if is_valid else "Failed: Invalid Syntax"
    except Exception as e:
        print(f"ERROR: validator crashed - {e}")
        is_valid = False
        validation_status = f"ValidatorError: {e}"

    print(f"INFO: Rule 검증 결과: {validation_status}")


     # 4) VirusTotal URL 요약 추가  
    try:
        vt_summary = vt_fetch_url_report(request.url, submit_if_absent=True, max_wait_sec=5)
        print(f"INFO: VT summary status={vt_summary.get('status')}")
    except Exception as e:
        vt_summary = {"status": "error", "detail": str(e)}



    # 5) 최종 응답
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
# /app.py

import os
import sys
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv

# 내부 모듈
from core.parser import get_text_from_url
from core.llm_handler import generate_analysis_from_text
# --- validator 임포트 수정 ---
from utils.validator import validate_rule # <- 통합 검증 함수 임포트
from core.vt_client import vt_fetch_url_report

# ──────────────────────────────────────────────────────────────────────────────
# 0) 환경 로드 및 사전 점검
# ──────────────────────────────────────────────────────────────────────────────
load_dotenv()

# GOOGLE_API_KEY 사용 가정
if not os.getenv("GOOGLE_API_KEY"):
    print("WARNING: GOOGLE_API_KEY not set. Set it in .env for AI Studio/Gemini API.")

# ──────────────────────────────────────────────────────────────────────────────
# 1) FastAPI 앱
# ──────────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="CTI-Rule-Generator API",
    description="CTI 문서를 분석하여 IDS Rule을 자동 생성하는 시스템의 API입니다.",
    version="1.1.0", # 버전 업데이트 (정적 분석 추가)
)

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

# ──────────────────────────────────────────────────────────────────────────────
# 4) 엔드포인트 (수정: validate_rule 사용 및 결과 처리)
# ──────────────────────────────────────────────────────────────────────────────
@app.post(
    "/api/generate-rule",
    response_model=RuleResponse,
    summary="CTI URL로부터 IDS Rule 생성",
    description="입력된 URL의 CTI 문서를 파싱, LLM으로 분석하여 IDS Rule을 생성하고 검증하며, VirusTotal 정보를 추가합니다.",
)
async def create_rule_from_url(request: RuleRequest):
    print(f"INFO: URL 수신: {request.url}")

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

# ──────────────────────────────────────────────────────────────────────────────
# 5) 실행
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("INFO: CTI-Rule-Generator API 서버를 시작합니다.")
    print("INFO: http://127.0.0.1:8000/docs 로 접속하세요.")
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
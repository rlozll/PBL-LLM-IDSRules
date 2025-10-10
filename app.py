# app.py

import os
import sys
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv

# 내부 모듈
from core.parser import get_text_from_url               # URL → 텍스트 파싱
from core.llm_handler import generate_analysis_from_text  # LLM 호출(이미 A안으로 수정했다고 했음)
from utils.validator import validate_rule_syntax        # Snort/Suricata 검증기
from core.vt_client import vt_fetch_url_report          # VirusTotal 클라이언트

# ──────────────────────────────────────────────────────────────────────────────
# 0) 환경 로드 및 사전 점검
# ──────────────────────────────────────────────────────────────────────────────
load_dotenv()

# A안에서는 반드시 GOOGLE_API_KEY(문자열)가 있어야 함.
# 서비스계정 키(JSON)는 사용하지 않는다. (GOOGLE_APPLICATION_CREDENTIALS 불필요)
if not os.getenv("GOOGLE_API_KEY"):
    print("WARNING: GOOGLE_API_KEY not set. Set it in .env for AI Studio.")
if os.getenv("GOOGLE_APPLICATION_CREDENTIALS"):
    print("INFO: GOOGLE_APPLICATION_CREDENTIALS is set, but A-option (AI Studio) does not need it. "
          "It will be ignored if GOOGLE_API_KEY is present.")

# ──────────────────────────────────────────────────────────────────────────────
# 1) FastAPI 앱
# ──────────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="CTI-Rule-Generator API",
    description="CTI 문서를 분석하여 IDS Rule을 자동 생성하는 시스템의 API입니다.",
    version="1.0.0",
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
    rule_explanation: str
    vt_summary: dict | None = None

# ──────────────────────────────────────────────────────────────────────────────
# 3) 유틸: Snort 룰 1차 형태검사(빠른 가드)
# ──────────────────────────────────────────────────────────────────────────────
def _is_probably_snort_rule(s: str) -> bool:
    """
    최소 형태 가드. LLM의 잘못된/설명성 텍스트가 Snort에 들어가는 것을 방지.
    멀티라인 룰도 각 라인 검증.
    """
    import re
    if not s or s.lower().startswith("error:"):
        return False
    lines = [L.strip() for L in s.strip().splitlines() if L.strip()]
    if not lines:
        return False
    pat = re.compile(r'^alert\s+\w+.*?msg:"[^"]+";.*?sid:\d+;.*?rev:\d+;.*?\)\s*$', re.I | re.S)
    return all(pat.search(L) for L in lines)

# ──────────────────────────────────────────────────────────────────────────────
# 4) 엔드포인트
# ──────────────────────────────────────────────────────────────────────────────
@app.post(
    "/api/generate-rule",
    response_model=RuleResponse,
    summary="CTI URL로부터 IDS Rule 생성",
    description="입력된 URL의 CTI 문서를 파싱, LLM으로 분석하여 IDS Rule을 생성하고 검증하며, VirusTotal 정보를 추가합니다.",
)
async def create_rule_from_url(request: RuleRequest):
    print(f"INFO: URL 수신: {request.url}")

    # 1) 파싱
    try:
        parsed_text = get_text_from_url(request.url)
        if not parsed_text or len(parsed_text) < 50:
            raise ValueError("파싱된 텍스트가 너무 짧습니다.")
        print(f"INFO: 텍스트 파싱 성공 (글자 수: {len(parsed_text)})")
    except Exception as e:
        print(f"ERROR: 파싱 실패 - {e}")
        raise HTTPException(status_code=400, detail=f"URL에서 텍스트를 파싱하는 데 실패했습니다: {e}")

    # 2) LLM 호출 (A안: AI Studio · API Key)
    #    6~12k자까지 1회 투입을 기본으로. 불필요한 청킹은 제거.
    text_for_llm = parsed_text
    print("INFO: LLM 분석용 텍스트 준비 완료 (전체 본문 사용)")

    llm_output = await generate_analysis_from_text(text_for_llm)

    # 실패면 즉시 종료(중요: 200 금지)
    if llm_output.get("error"):
        # 어떤 스테이지에서 실패했는지 간단 표기
        stage = "ioc" if "IOC" in llm_output["error"] else "rule" if "RULE" in llm_output["error"] else "llm"
        print(f"ERROR: LLM 처리 실패 - {llm_output['error']}")
        raise HTTPException(
            status_code=502,
            detail={"stage": stage, "error": llm_output["error"], "detail": llm_output.get("explanation", "")},
        )

    extracted_ioc = llm_output.get("ioc", {})
    rule_to_validate = (llm_output.get("rule") or "").strip()
    explanation = llm_output.get("explanation", "설명 없음.")

    if not rule_to_validate:
        print("ERROR: LLM 결과에 Rule이 없음")
        raise HTTPException(status_code=500, detail="LLM이 유효한 Rule을 생성하지 못했습니다.")

    # 3) Snort 사전검증(정규식)
    if not _is_probably_snort_rule(rule_to_validate):
        print("ERROR: 사전검증 실패 - Snort 형태에 맞지 않음")
        raise HTTPException(
            status_code=400,
            detail={"stage": "validate", "error": "precheck failed", "rule": rule_to_validate[:300]},
        )

    # 4) Snort 검증기 실행 (WSL/로컬 환경에 맞게 utils.validator가 처리)
    try:
        if sys.platform == "darwin":
            validation_status = "Skipped on macOS"
        else:
            is_valid = validate_rule_syntax(rule_to_validate, engine="snort")
            validation_status = "Success: Valid Syntax" if is_valid else "Failed: Invalid Syntax"
    except Exception as e:
        print(f"ERROR: validator 모듈 실행 중 충돌 - {e}")
        validation_status = f"ValidatorError: {e}"
    print(f"INFO: Rule 검증 결과: {validation_status}")

    # 5) VirusTotal (선택)
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

    # 6) 최종 응답
    return RuleResponse(
        source_url=request.url,
        extracted_ioc=extracted_ioc,
        generated_rule=rule_to_validate,
        validation_result=validation_status,
        rule_explanation=explanation,
        vt_summary=vt_summary,
    )

# ──────────────────────────────────────────────────────────────────────────────
# 5) 실행
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("INFO: CTI-Rule-Generator API 서버를 시작합니다.")
    print("INFO: http://127.0.0.1:8000/docs 로 접속하세요.")
    uvicorn.run(app, host="127.0.0.1", port=8000)

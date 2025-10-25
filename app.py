# app.py

import os
import sys
import uvicorn
import asyncio
from typing import Dict, Any, Optional
from urllib.parse import unquote_plus

from pathlib import Path   
from fastapi import FastAPI, HTTPException, Request, UploadFile, File
from pydantic import BaseModel
from dotenv import load_dotenv

# 내부 모듈 (기존)
from core.parser import get_text_from_url               # URL → 텍스트 파싱
from core.llm_handler import generate_analysis_from_text  # LLM 호출(이미 A안으로 수정했다고 했음)
from utils.validator import validate_rule_syntax        # Snort/Suricata 검증기
from core.vt_client import vt_fetch_url_report          # VirusTotal 클라이언트

# ─────────────────────────────────────────────
# .env 절대경로 로드 (uvicorn reloader에서도 확실히 적용)
# ─────────────────────────────────────────────
ENV_PATH = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=str(ENV_PATH))


# 새로 추가한 NVD 클라이언트(작성해 둔 core/nvd_client.py 사용)
# core/nvd_client.py에 search_from_text, query_nvd_by_keyword, query_nvd_by_cve 등을 구현해 둬야 함.
from core.nvd_client import (
    search_from_text,
    query_nvd_by_keyword,
    query_nvd_by_cve,
    extract_cve_ids_from_text,
)


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

# 간단한 NVD 키 마스크/존재 체크
NVD_API_KEY = os.getenv("NVD_API_KEY") or os.getenv("NVD_APIKEY") or os.getenv("NVD_KEY")
def _mask_key(k: Optional[str]) -> Optional[str]:
    if not k:
        return None
    return k[:4] + "***" + k[-4:]

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
# 4) 기존 엔드포인트: Rule 생성 (변경 없음 — 동작 유지)
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
        # 기존 코드는 동기 get_text_from_url을 사용하므로 그대로 호출
        parsed_text = get_text_from_url(request.url)
        if not parsed_text or len(parsed_text) < 50:
            raise ValueError("파싱된 텍스트가 너무 짧습니다.")
        print(f"INFO: 텍스트 파싱 성공 (글자 수: {len(parsed_text)})")
    except Exception as e:
        print(f"ERROR: 파싱 실패 - {e}")
        raise HTTPException(status_code=400, detail=f"URL에서 텍스트를 파싱하는 데 실패했습니다: {e}")

    # 2) LLM 호출 (A안: AI Studio · API Key)
    text_for_llm = parsed_text
    print("INFO: LLM 분석용 텍스트 준비 완료 (전체 본문 사용)")

    llm_output = await generate_analysis_from_text(text_for_llm)

    # 실패면 즉시 종료(중요: 200 금지)
    if llm_output.get("error"):
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
# 5) NVD / Debug 관련 엔드포인트 추가
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/api/debug/env", summary="환경 디버그 (키 존재 여부 확인)")
async def debug_env():
    env_path = os.path.join(os.getcwd(), ".env")
    masked = _mask_key(NVD_API_KEY)
    return {"env_path": env_path, "nvd_api_key_present": bool(NVD_API_KEY), "nvd_api_key_masked": masked}


@app.get("/api/nvd/raw", summary="NVD raw 호출 (cveId 또는 keywordSearch)")
async def nvd_raw(request: Request):
    """
    쿼리 파라미터:
      - cveId=CVE-YYYY-NNNN  (우선순위)
      - keywordSearch=... & resultsPerPage=...
    이 엔드포인트는 NVD 직접 호출 결과(원본 JSON 또는 에러 메시지)를 반환함.
    """
    qp = dict(request.query_params)
    # 우선 cveId
    if "cveId" in qp:
        cid = qp["cveId"]
        data = await asyncio.to_thread(query_nvd_by_cve, cid)
        if data is None:
            raise HTTPException(status_code=502, detail=f"NVD single CVE lookup failed for {cid}")
        return {"ok": True, "source": "nvd", "cveId": cid, "data": data}

    # keywordSearch fallback
    ks = qp.get("keywordSearch") or qp.get("keyword")
    if ks:
        # resultsPerPage optional
        rpp = int(qp.get("resultsPerPage") or qp.get("results") or 50)
        data = await asyncio.to_thread(query_nvd_by_keyword, ks, results_per_page=rpp)
        if data is None:
            raise HTTPException(status_code=502, detail=f"NVD keywordSearch failed for '{ks}'")
        return {"ok": True, "source": "nvd", "keyword": ks, "data": data}

    raise HTTPException(status_code=400, detail="cveId 또는 keywordSearch 파라미터 필요")


@app.get("/api/nvd/parsed", summary="URL에서 텍스트 추출 후 NVD 검색(파싱+통합결과)")
async def nvd_parsed(url: str):
    """
    사용법:
      GET /api/nvd/parsed?url=https://example.com/...
    동작:
      1) URL에서 텍스트 파싱
      2) 텍스트에서 CVE 추출 → 단건 조회
      3) (필요시) keywordSearch 시도, MITRE/CIRCL 폴백까지 포함한 search_from_text 결과 반환
    """
    if not url:
        raise HTTPException(status_code=400, detail="url required")
    try:
        # parser.get_text_from_url가 동기라면 스레드에서 실행
        text = await asyncio.to_thread(get_text_from_url, url)
        if not text or len(text) < 20:
            raise HTTPException(status_code=400, detail="파싱된 텍스트가 너무 짧음")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"페이지 파싱 실패: {e}")

    result = await asyncio.to_thread(search_from_text, text)
    return {"ok": True, "source_url": url, "nvd_search": result}


@app.post("/api/nvd/from-url", summary="POST: JSON {url:...} -> URL에서 텍스트 파싱 후 NVD 검색")
async def nvd_from_url(payload: Dict[str, Any]):
    url = payload.get("url")
    if not url:
        raise HTTPException(status_code=400, detail="url 필수")
    try:
        text = await asyncio.to_thread(get_text_from_url, url)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"페이지 파싱 실패: {e}")

    result = await asyncio.to_thread(search_from_text, text)
    return {"ok": True, "source_url": url, "nvd_search": result}


@app.post("/api/nvd/from-pdf", summary="PDF 업로드 -> 텍스트 추출 -> NVD 검색")
async def nvd_from_pdf(file: UploadFile = File(...)):
    """
    multipart/form-data로 PDF 파일 업로드.
    반환: search_from_text()의 결과 구조
    """
    if not file:
        raise HTTPException(status_code=400, detail="file 필요")
    contents = await file.read()
    try:
        from io import BytesIO
        import PyPDF2
        reader = PyPDF2.PdfReader(BytesIO(contents))
        pages = []
        for p in reader.pages:
            pages.append(p.extract_text() or "")
        text = "\n".join(pages)
        if not text.strip():
            raise HTTPException(status_code=400, detail="PDF에서 텍스트를 추출하지 못함")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"PDF 파싱 실패: {e}")

    result = await asyncio.to_thread(search_from_text, text)
    return {"ok": True, "filename": file.filename, "nvd_search": result}


# ──────────────────────────────────────────────────────────────────────────────
# 6) 실행
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("INFO: CTI-Rule-Generator API 서버를 시작합니다.")
    print("INFO: http://127.0.0.1:8000/docs 로 접속하세요.")
    uvicorn.run(app, host="127.0.0.1", port=8000, reload=True)
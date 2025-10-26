# llm_handler.py
import os, json, asyncio
import google.generativeai as genai
from google.generativeai import types as genai_types
from pydantic import BaseModel, Field
from typing import List

MODEL = os.getenv("LLM_MODEL", "gemini-2.5-flash")

# 1) IoC 스키마 정의 (필요 필드만, 전부 optional 리스트로)
class IoC(BaseModel):
    cve: List[str] = Field(default_factory=list)
    ip: List[str] = Field(default_factory=list)
    domain: List[str] = Field(default_factory=list)
    url: List[str] = Field(default_factory=list)
    hash: List[str] = Field(default_factory=list)

def _configure():
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        raise RuntimeError("GOOGLE_API_KEY not set")
    genai.configure(api_key=api_key)

def _extract_text(resp) -> str:
    # resp.text가 비어있을 수 있음 → candidates/parts에서 재조립
    txt = (getattr(resp, "text", None) or "").strip()
    if txt:
        return txt
    # fallback: parts 순회
    try:
        for cand in getattr(resp, "candidates", []):
            for part in getattr(cand, "content", {}).parts:  # SDK 구조상 content.parts
                if hasattr(part, "text") and part.text:
                    return part.text.strip()
    except Exception:
        pass
    return ""

async def call_gemini(prompt: str, *, json_mode=False, schema=None) -> tuple[str, str]:
    try:
        _configure()
        model = genai.GenerativeModel(MODEL)

        genconf = {}
        if json_mode:
            genconf["response_mime_type"] = "application/json"
            if schema is not None:
                genconf["response_schema"] = schema  # Pydantic BaseModel OK

        resp = await asyncio.to_thread(
            lambda: model.generate_content(
                prompt,
                generation_config=genconf if genconf else None,
            )
        )

        text = _extract_text(resp)
        if not text:
            return "", "Empty response text"
        return text, ""
    except Exception as e:
        return "", f"{type(e).__name__}: {e}"
    

def _json_coerce(s: str) -> tuple[dict, str]:
    """JSON 파싱 수비수: 코드블록/앞뒤 잡소리 제거 + {} 추출"""
    try:
        return json.loads(s), ""
    except Exception:
        pass
    # 코드블록 제거
    if "```" in s:
        parts = [p.strip() for p in s.split("```") if p.strip()]
        s = parts[-1]
    # 본문에서 가장 바깥 { ... } 추출
    import re
    m = re.search(r"\{.*\}", s, flags=re.S)
    if m:
        try:
            return json.loads(m.group(0)), ""
        except Exception as e:
            return {}, f"JSON_EXTRACT_FAIL: {e}"
    return {}, "No JSON object found"

async def generate_analysis_from_text(text: str) -> dict:
    # 1) IoC 추출 (구조화 출력 강제)
    ioc_prompt = f"""
다음 CTI 본문에서 IoC를 '한 개의 JSON 객체'로만 출력하라.
키: cve, ip, domain, url, hash (모두 리스트). 설명, 주석, 텍스트 금지.
본문:
{text[:12000]}
"""
    ioc_text, err = await call_gemini(ioc_prompt, json_mode=True, schema=IoC)
    if err:
        return {"error": f"IOC_FAILED: {err}", "ioc": {}, "rule": "", "explanation": err}

    ioc_json, perr = _json_coerce(ioc_text)
    if perr:
        return {"error": f"IOC_JSON_PARSE_FAILED: {perr}", "raw": ioc_text, "ioc": {}, "rule": "", "explanation": perr}

    # 2) Rule 생성
    rule_prompt = f"""
다음 IoC를 기반으로 Snort 2.9 규칙 1개만 생성하여 출력하라. 코드블록/설명 금지, 규칙 한 줄만 출력.
필수 항목: msg, sid(>=1000000), rev(>=1), reference(CVE). content 또는 pcre 사용.
classtype 옵션은 포함하지 않아도 된다.

IoC:
{json.dumps(ioc_json, ensure_ascii=False, indent=2)}
"""
    rule_text, err = await call_gemini(rule_prompt, json_mode=False)
    if err:
        return {"error": f"RULE_FAILED: {err}", "ioc": ioc_json, "rule": "", "explanation": err}

    rule_text = rule_text.strip()
    if "```" in rule_text:
        parts = [p.strip() for p in rule_text.split("```") if p.strip()]
        rule_text = parts[-1]

    # 간단 형태검사 (기존과 동일)
    import re
    pat = re.compile(r'^alert\s+\w+.*?msg:"[^"]+";.*?sid:\d+;.*?rev:\d+;.*?\)\s*$', re.I | re.S)
    lines = [L.strip() for L in rule_text.splitlines() if L.strip()]
    if not lines or not all(pat.search(L) for L in lines):
        return {"error": "RULE_PRECHECK_FAILED", "ioc": ioc_json, "rule": rule_text, "explanation": "precheck failed"}

    return {"ioc": ioc_json, "rule": rule_text, "explanation": f"model={MODEL}"}

# core/llm_handler.py
import os, json, asyncio
import google.generativeai as genai
from pydantic import BaseModel, Field
from typing import List
import re
from dotenv import load_dotenv

# --- 환경 변수 설정 및 모델 정의 ---
load_dotenv()
api_key = os.getenv("GOOGLE_API_KEY")
if not api_key:
    print("ERROR: GOOGLE_API_KEY is not set in .env file!")
else:
    genai.configure(api_key=api_key)

MODEL = os.getenv("LLM_MODEL", "gemini-pro")

# --- IoC 스키마 정의 ---
class IoC(BaseModel):
    cve: List[str] = Field(default_factory=list)
    ip: List[str] = Field(default_factory=list)
    domain: List[str] = Field(default_factory=list)
    url: List[str] = Field(default_factory=list)
    hash: List[str] = Field(default_factory=list)

# --- Gemini 응답 텍스트 추출 함수 ---
def _extract_text(resp) -> str:
    # (기존 코드와 동일 - 생략)
    txt = (getattr(resp, "text", None) or "").strip()
    if txt: return txt
    try:
        for cand in getattr(resp, "candidates", []):
            if cand.content and cand.content.parts:
                 first_part_text = getattr(cand.content.parts[0], "text", None)
                 if first_part_text: return first_part_text.strip()
            finish_reason = getattr(cand, "finish_reason", 0)
            if finish_reason != 1:
                 print(f"WARNING: Gemini 응답 비정상 종료 (Reason: {finish_reason})")
                 safety_ratings = getattr(cand, "safety_ratings", [])
                 if safety_ratings: print(f"DEBUG: Safety Ratings - {safety_ratings}")
                 return f"Error: Response blocked due to safety settings (Reason: {finish_reason})."
    except Exception as e:
        print(f"DEBUG: _extract_text 중 예외 발생 - {e}")
        pass
    return ""


# --- Gemini API 호출 함수 ---
async def call_gemini(prompt: str, *, json_mode=False) -> tuple[str, str]:
    # (기존 코드와 동일 - schema 파라미터 없음)
    try:
        model = genai.GenerativeModel(MODEL)
        genconf = {"response_mime_type": "application/json"} if json_mode else {}
        resp = await asyncio.to_thread(
            lambda: model.generate_content(
                prompt,
                generation_config=genconf if genconf else None,
                safety_settings={'HATE': 'BLOCK_NONE', 'HARASSMENT': 'BLOCK_NONE', 'SEXUAL' : 'BLOCK_NONE', 'DANGEROUS' : 'BLOCK_NONE'}
            )
        )
        text = _extract_text(resp)
        if text.startswith("Error: Response blocked"): return "", text
        if not text:
            print(f"DEBUG: Gemini 응답 비었음. Response object: {resp}")
            return "", "Empty response text"
        return text, ""
    except Exception as e:
        print(f"ERROR: Gemini API 호출 중 오류 - {e}")
        return "", f"{type(e).__name__}: {e}"

# --- JSON 파싱 보조 함수 ---
def _json_coerce(s: str) -> tuple[dict, str]:
    # (기존 코드와 동일 - 생략)
    try: return json.loads(s), ""
    except Exception: pass
    if "```" in s:
        parts = [p.strip() for p in s.split("```") if p.strip()]
        s = parts[-1].lstrip("json\n")
    m = re.search(r"\{.*\}", s, flags=re.S)
    if m:
        try: return json.loads(m.group(0)), ""
        except Exception as e: return {}, f"JSON_EXTRACT_FAIL: {e}"
    return {}, "No JSON object found"

# --- 메인 분석 함수 ---
async def generate_analysis_from_text(text: str) -> dict:
    # 1) IoC 추출
    print("INFO: Gemini 호출 시작 - 1단계: IoC 추출")
    ioc_prompt = f"""
다음 CTI 본문에서 IoC를 '한 개의 JSON 객체'로만 출력하라.
키: cve, ip, domain, url, hash (모두 문자열 리스트). 해당하는 내용이 없으면 빈 리스트 `[]`를 사용. 설명, 주석, 텍스트 금지.
반드시 JSON 형식만 응답해야 한다.
본문:
{text[:12000]}
유효하고 도움이 되는 정보에 대해 IoC(침해 지표)를 추출하라. 
"""
    ioc_text, err = await call_gemini(ioc_prompt, json_mode=True)
    if err:
        return {"error": f"IOC_FAILED: {err}", "ioc": {}, "rule": "", "explanation": err}
    ioc_json, perr = _json_coerce(ioc_text)
    if perr:
        print(f"ERROR: IOC JSON 파싱 실패. Raw text: {ioc_text}")
        return {"error": f"IOC_JSON_PARSE_FAILED: {perr}", "raw": ioc_text, "ioc": {}, "rule": "", "explanation": perr}
    print(f"INFO: Gemini 결과 - 추출된 IoC: {ioc_json}")

    # 2) Rule 생성
    print("INFO: Gemini 호출 시작 - 2단계: Snort Rule 생성")
    rule_prompt = f"""
다음 IoC를 기반으로 Snort 2.9 규칙 1개만 생성하여 출력하라. 코드블록/설명 금지, 규칙 한 줄만 출력.
필수 항목: msg, sid(>=1000000), rev(>=1), reference(CVE). content 또는 pcre 사용.
classtype 옵션은 포함하지 않아도 된다.
프로토콜은 반드시 [tcp, udp, ip] 중 하나를 사용해야 한다. HTTP 트래픽 탐지 시에는 tcp를 사용해야 한다.
IoC:
{json.dumps(ioc_json, ensure_ascii=False, indent=2)}
또한, Snort는 pcre regex를 문자열로 보는 게 아니라 규칙 언어의 일부로 보기 때문에, 정규식이 PCRE 문법이 아닌 Snort 전용 구문에 따라야 한다.
무조건 Snort 2.9 버전에 맞춘 규칙이어야 한다. 그리고 성능이 좋고 뛰어난, 실제 IDS에 배포했을 때 적용 가능할만한 Rule이어야 한다. 
그리고 검증 가능한 Rule이어야 한다. 현재 이 시스템은 정적 검증과 실제 Snort 2.9 엔진을 호출해 문법적 검증도 진행한다. 이 검증 단계에 통과해야 하는 Rule이어야 한다. 
또한 Behavior 기반으로 도메인이나 파일명이 아닌, 공격 코드가 실행될 때 나오는 패턴을 잡아서 생성되는 Rule이어야 한다. PCRE 방식을 활용해라.
입력한 문서에만 해당하는 Rule이 아니라, 해당 사건에 대해서는 모두 탐지해야 할 줄 아는 Rule이어야 한다. 
또한 PCRE 문법에서 여는 괄호'('가 있다면 닫는 괄호')'도 있어야 한다. 즉, 괄호의 짝이 맞아야 한다.
그리고 마지막으로 강조하지만, 검증에 꼭 성공해야 한다.
"""
    rule_text, err = await call_gemini(rule_prompt, json_mode=False)
    if err:
        return {"error": f"RULE_FAILED: {err}", "ioc": ioc_json, "rule": "", "explanation": err}

    # (Rule 텍스트 정리 로직 - 기존과 동일, 생략)
    rule_text = rule_text.strip()
    if "```" in rule_text:
        match = re.search(r"```(?:snort|rule)?\n(.*?)```", rule_text, re.DOTALL | re.IGNORECASE)
        if match: rule_text = match.group(1).strip()
        else:
             parts = [p.strip() for p in rule_text.split("```") if p.strip()]
             rule_text = parts[-1]
    if not rule_text.lower().startswith("alert"):
         lines = rule_text.splitlines()
         for line in lines:
             if line.strip().lower().startswith("alert"):
                 rule_text = line.strip()
                 break
    print(f"INFO: Gemini 결과 - 생성된 Rule: {rule_text}")

    # ▼▼▼▼▼ 3단계: Rule 설명 생성 (JSON 형식으로 요청) ▼▼▼▼▼
    print("INFO: Gemini 호출 시작 - 3단계: Rule 설명 생성")
    explanation_json = {"error": "설명 생성 실패"} # 기본값 설정
    if rule_text and not rule_text.startswith("Error:"):
        explanation_prompt = f"""
당신은 CTI 분석가이자 보안 교육 전문가입니다.
아래 추출된 IoC와 생성된 Snort Rule을 바탕으로, 요청한 3가지 항목을 포함하는 **JSON 객체**로 응답해주세요.
모든 설명은 한국어로 작성해야 합니다.

1.  **"rule_analysis"**: 이 규칙이 왜 필요하며 어떤 원리로 공격을 탐지하는지 전문가용으로 설명해주세요. (예: 어떤 content/pcre가 어떤 공격 패턴을 잡는지)
2.  **"ids_recommendation"**: 이 규칙을 더 효과적으로 적용하기 위한 IDS 설정 변경 제안이 있나요? (예: `any any -> $HTTP_SERVERS $HTTP_PORTS`로 변경 제안, 또는 특정 포트 감시 필요 등)
3.  **"user_action"**: 이 위협에 대해 보안을 모르는 일반 사용자나 개발자가 무엇을 해야 하는지 간단하게 설명해주세요. (예: 즉시 Log4j 라이브러리 패치, 의심스러운 로그 확인 등)

--- 추출된 IoC ---
{json.dumps(ioc_json, ensure_ascii=False, indent=2)}

--- 생성된 Snort Rule ---
{rule_text}

--- JSON 응답 ---
"""
        explanation_text, err = await call_gemini(explanation_prompt, json_mode=True)
        if not err:
            explanation_json, perr = _json_coerce(explanation_text)
            if perr:
                print(f"WARNING: 설명 JSON 파싱 실패 - {perr}, Raw: {explanation_text}")
                explanation_json = {"error": "설명 JSON 파싱 실패", "raw": explanation_text}
            else:
                 print(f"INFO: Gemini 결과 - 생성된 설명 (JSON): {explanation_json}")
        else:
            print(f"WARNING: 설명 생성 실패 - {err}")
            explanation_json = {"error": f"설명 생성 중 오류 발생: {err}"}
    else:
        explanation_json = {"error": "Rule 생성 실패로 설명 생성 안 함."}

    # 4) 최종 결과 반환
    return {"ioc": ioc_json, "rule": rule_text, "explanation": explanation_json}
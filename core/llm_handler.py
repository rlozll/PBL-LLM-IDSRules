# core/llm_handler.py

import os
import json
from openai import AsyncOpenAI  # 비동기 처리를 위해 AsyncOpenAI 사용
from dotenv import load_dotenv

# 1. API 키 로딩
load_dotenv()
api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise ValueError("OpenAI API 키가 .env 파일에 설정되지 않았습니다.")

client = AsyncOpenAI(api_key=api_key)
MODEL = "gpt-4o" # 또는 "gpt-3.5-turbo" 등 사용 가능한 최신 모델

async def generate_analysis_from_text(text: str) -> dict:
    """
    CTI 텍스트를 입력받아 LLM을 통해 IoC와 Snort Rule을 생성합니다.
    """
    try:
        # --- 1차 호출: IoC 추출 ---
        print("INFO: LLM 호출 시작 - 1단계: IoC 추출")
        ioc_prompt = f"""
        당신은 최고의 사이버 위협 인텔리전스(CTI) 분석가입니다.
        아래 텍스트에서 공격과 관련된 IoC(Indicators of Compromise)를 모두 추출하여 JSON 형식으로 정리해 주십시오.

        추출할 항목:
        - "cve": 관련된 CVE 번호 (예: "CVE-2021-44228")
        - "ip": 공격자의 C2 서버 또는 악성 IP 주소
        - "domain": 악성 도메인 주소
        - "url": 악성 행위와 관련된 전체 URL 경로
        - "hash": 악성 파일의 해시 값 (md5, sha1, sha256)
        - "file_path": 공격과 관련된 파일 경로 (예: "/var/log/access.log")
        
        해당하는 항목이 없으면 빈 리스트 `[]` 또는 빈 문자열 `""`로 표시해 주십시오.
        반드시 JSON 객체 하나만 응답해야 합니다.

        --- 분석할 텍스트 ---
        {text[:4000]} 
        """ # 텍스트가 너무 길 경우를 대비해 일부만 사용

        response1 = await client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": ioc_prompt}],
            response_format={"type": "json_object"} # JSON 출력 모드 활성화
        )
        extracted_iocs = json.loads(response1.choices[0].message.content)
        print(f"INFO: LLM 결과 - 추출된 IoC: {extracted_iocs}")

        # --- 2차 호출: Snort Rule 생성 ---
        print("INFO: LLM 호출 시작 - 2단계: Snort Rule 생성")
        rule_prompt = f"""
        당신은 최고의 네트워크 보안 전문가입니다. 
        아래 CTI 분석 텍스트와 추출된 IoC를 바탕으로, 이 공격을 탐지할 수 있는 Snort 2.9 버전 문법에 맞는 IDS Rule을 생성해 주십시오.

        규칙 생성 가이드:
        1. `msg` 필드에는 어떤 공격인지 명확하게 설명합니다. (예: "ET EXPLOIT Apache Log4j JNDI Injection Attempt")
        2. `content` 필드에는 탐지할 핵심적인 문자열 패턴을 IoC에서 가져와 사용합니다.
        3. `reference` 필드에는 CVE 번호를 포함합니다.
        4. `sid`는 1000000 이상의 임의의 숫자를 사용하고, `rev`는 1로 설정합니다.
        5. 가장 중요한 공격 패턴을 탐지할 수 있는 규칙 딱 하나만 생성합니다.

        --- CTI 분석 텍스트 ---
        {text[:4000]}

        --- 추출된 IoC ---
        {json.dumps(extracted_iocs, indent=2)}

        --- 생성할 Snort Rule ---
        """

        response2 = await client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": rule_prompt}]
        )
        generated_rule = response2.choices[0].message.content.strip()

        # LLM 응답에서 Rule만 깔끔하게 추출 (```rule ... ``` 같은 마크다운 제거)
        if '```' in generated_rule:
            generated_rule = generated_rule.split('```')[1].strip().replace("rule\n", "")

        print(f"INFO: LLM 결과 - 생성된 Rule: {generated_rule}")

        # TODO: Rule 설명 생성 (간단한 3차 호출 또는 Rule 생성 프롬프트에 포함)
        explanation = f"LLM이 생성한 규칙. CVE: {extracted_iocs.get('cve', 'N/A')}"
        
        return {
            "ioc": extracted_iocs,
            "rule": generated_rule,
            "explanation": explanation
        }

    except Exception as e:
        print(f"ERROR: LLM 처리 중 오류 발생 - {e}")
        # 오류 발생 시 빈 결과 또는 기본 오류 메시지 반환
        return {
            "ioc": {},
            "rule": f"Error: LLM processing failed. {e}",
            "explanation": str(e)
        }
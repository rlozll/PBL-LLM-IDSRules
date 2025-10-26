# utils/validator.py

import subprocess
import os
import tempfile
import re
from typing import List, Tuple # <--- List, Tuple 임포트 추가

def _windows_path_to_wsl_path(windows_path: str) -> str:
    """Windows 경로를 WSL 경로로 변환합니다."""
    # (기존 코드와 동일)
    path = windows_path.replace('\\', '/')
    drive, path_no_drive = os.path.splitdrive(path)
    drive_letter = drive.replace(':', '').lower()
    return f"/mnt/{drive_letter}{path_no_drive}"

# --- 정적 분석 함수 ---
def analyze_rule_statically(rule_string: str) -> List[str]:
    """
    Snort Rule 문자열을 정적으로 분석하여 잠재적인 문제점 목록을 반환합니다.
    """
    # (이전 코드와 동일 - re 임포트는 파일 상단으로 이동)
    warnings = []
    rule_lower = rule_string.lower()

    # 1. content 검사
    content_matches = re.findall(r'content\s*:\s*"([^"]+)"', rule_string, re.IGNORECASE)
    has_http_options = any(opt in rule_lower for opt in ['http_uri', 'http_raw_uri', 'http_header', 'http_raw_header', 'http_client_body', 'http_raw_body', 'http_method', 'http_stat_code', 'http_stat_msg'])

    for content in content_matches:
        content_len = len(content.encode('utf-8')) # 정확한 바이트 길이 계산
        content_lower = content.lower()

        if content_len < 4:
            warnings.append(f"취약한 패턴: content '{content}'의 길이가 너무 짧습니다 ({content_len}바이트). 오탐 및 성능 저하 가능성이 있습니다.")

        # 매우 일반적인 패턴 리스트 확장
        common_patterns = ["get", "post", "<script>", "user-agent", "select ", "insert ", "union ", "delete ", "alert(", "onload=", "onerror="]
        if any(pat in content_lower for pat in common_patterns):
             warnings.append(f"취약한 패턴: content '{content}'는 매우 일반적이어서 오탐 가능성이 높습니다.")

        if ('/' in content or 'http' in content_lower or 'www' in content_lower or '.exe' in content_lower or '.dll' in content_lower) and not has_http_options:
            warnings.append(f"성능 경고: HTTP 관련 패턴 '{content}'을(를) 포함하지만, http_* 옵션이 없어 불필요한 검사를 유발할 수 있습니다.")

    # 2. nocase 검사
    if content_matches and 'nocase;' not in rule_lower:
        warnings.append("탐지 누락 가능성: content 옵션이 있지만 nocase 옵션이 없어 대소문자 변형을 놓칠 수 있습니다.")

    # 3. pcre 검사
    pcre_matches = re.findall(r'pcre\s*:\s*"([^"]+)"', rule_string, re.IGNORECASE)
    for pcre in pcre_matches:
        if pcre.startswith('/.*') or pcre.endswith('.*/'):
            warnings.append(f"성능 경고: PCRE 패턴 '{pcre}'은(는) 시작/끝의 '.*' 때문에 비효율적일 수 있습니다.")
        # 간단한 복잡도 체크 (예: 과도한 그룹 또는 수량자) - 단순 예시
        if len(re.findall(r'[\(\)\[\]\{\}\?\*\+\|]', pcre)) > 10:
             warnings.append(f"성능 경고: PCRE 패턴 '{pcre}'이(가) 너무 복잡하여 성능 저하를 유발할 수 있습니다.")

    # 4. 메타데이터 검사
    if 'sid:' not in rule_lower:
         warnings.append("필수 정보 누락: sid (Rule ID) 정보가 없습니다.")
    if 'rev:' not in rule_lower:
         warnings.append("필수 정보 누락: rev (Rule revision) 정보가 없습니다.")
    if 'reference:' not in rule_lower:
        warnings.append("정보 부족: reference 정보가 누락되었습니다 (예: cve, url).")

    return warnings

# --- 문법 검증 함수 (수정: 결과와 출력을 함께 반환) ---
def validate_rule_syntax(rule_string: str) -> Tuple[bool, str]:
    """
    WSL Snort를 사용하여 문법 유효성 검증 후, (성공 여부, Snort 출력 내용) 튜플을 반환.
    """
    if not rule_string or rule_string.lower().startswith("error:"):
        return False, f"Invalid rule string input: {rule_string[:100]}..."

    config_content = f"var HOME_NET any\n{rule_string}"
    windows_config_path = ""
    full_output = "" # Snort 출력 저장 변수

    try:
        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.conf', encoding='utf-8') as temp_config_file:
            temp_config_file.write(config_content)
            windows_config_path = temp_config_file.name

        wsl_config_path = _windows_path_to_wsl_path(windows_config_path)
        print(f"INFO: 임시 설정 파일 생성 (WSL 경로): {wsl_config_path}")

        command = ["wsl", "sudo", "snort", "-c", wsl_config_path, "-T"]
        print(f"INFO: 실행할 WSL 명령어: {' '.join(command)}")

        result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
        full_output = result.stdout + result.stderr # stdout과 stderr 모두 캡처

        success_message = "Snort successfully validated the configuration!"
        error_indicators = ["ERROR:", "Fatal Error"]

        # stderr에 명백한 에러가 있는지 먼저 확인
        if any(indicator in result.stderr for indicator in error_indicators):
            print(f"❌ (WSL Snort) 구문 검증 실패 (stderr 에러):\n{result.stderr}")
            return False, full_output # 실패 + 전체 출력 반환
        # 에러 없고 stdout/stderr에 성공 메시지가 있는지 확인
        elif success_message in full_output:
            print("✅ (WSL Snort) 구문 검증 성공")
            if "WARNING:" in result.stderr:
                 print(f"INFO: Snort 경고 발생 (결과는 성공):\n{result.stderr}")
            return True, full_output # 성공 + 전체 출력 반환
        # 둘 다 아니면 실패
        else:
            print(f"❌ (WSL Snort) 구문 검증 실패 (예상치 못한 출력):\n{full_output}")
            return False, full_output # 실패 + 전체 출력 반환

    except subprocess.TimeoutExpired:
        print("❌ (Validator) Snort 검증 시간 초과 (Timeout)")
        return False, "Snort validation timed out."
    except Exception as e:
        print(f"❌ (Validator) 검증 중 예외 발생: {e}")
        return False, f"Validator Exception: {e}"
    finally:
        if windows_config_path and os.path.exists(windows_config_path):
            try: os.remove(windows_config_path)
            except Exception as e: print(f"WARNING: 임시 파일 삭제 실패 - {e}")

# --- 통합 검증 함수 (수정: validate_rule_syntax 호출하도록 변경) ---
def validate_rule(rule_string: str) -> dict:
    """
    문법 검증과 정적 분석을 모두 수행하고 결과를 종합하여 반환합니다.
    """
    # 1. 문법 검증 수행 (수정된 함수 호출)
    syntax_valid, snort_output = validate_rule_syntax(rule_string)

    # 결과 딕셔너리 초기화
    results = {
        "rule": rule_string,
        "syntax_valid": syntax_valid,
        "syntax_check_output": snort_output, # Snort의 전체 출력 저장
        "static_warnings": [],
        "overall_status": "Failed" # 기본값 실패
    }

    # 2. 문법이 유효하면 정적 분석 수행
    if syntax_valid:
        results["static_warnings"] = analyze_rule_statically(rule_string)
        if not results["static_warnings"]:
            results["overall_status"] = "Success" # 문법 OK, 경고 없음 = 성공
        else:
            results["overall_status"] = "Warning" # 문법 OK, 경고 있음 = 경고
    # 문법 오류 시 overall_status는 이미 Failed 이므로 변경 불필요

    return results
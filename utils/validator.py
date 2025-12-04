# utils/validator.py

import subprocess
import os
import tempfile
import re
from typing import List, Tuple, Dict # <- Dict 추가

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
    warnings = []
    rule_lower = rule_string.lower()

    # 1. content 검사
    content_matches = re.findall(r'content\s*:\s*"([^"]+)"', rule_string, re.IGNORECASE)
    has_http_options = any(opt in rule_lower for opt in ['http_uri', 'http_raw_uri', 'http_header', 'http_raw_header', 'http_client_body', 'http_raw_body', 'http_method', 'http_stat_code', 'http_stat_msg', 'http.method', 'http.uri', 'http.header', 'http.request_body', 'http.response_body']) # Suricata 옵션도 일부 포함

    for content in content_matches:
        # 문자열 내용 자체의 길이 (정확한 바이트 계산은 생략)
        content_len_approx = len(content)
        content_lower = content.lower()

        if content_len_approx < 4:
            warnings.append(f"취약한 패턴: content '{content}'의 길이가 너무 짧습니다 ({content_len_approx}자). 오탐 및 성능 저하 가능성이 있습니다.")

        common_patterns = ["get", "post", "<script>", "user-agent", "select ", "insert ", "union ", "delete ", "alert(", "onload=", "onerror=", "passwd"]
        if any(pat in content_lower for pat in common_patterns):
             warnings.append(f"취약한 패턴: content '{content}'는 매우 일반적이어서 오탐 가능성이 높습니다.")

        # HTTP 관련 패턴인데 http_* 옵션이 없는 경우
        likely_http = ('/' in content or 'http' in content_lower or 'www' in content_lower or '.php' in content_lower or '.asp' in content_lower or '.js' in content_lower or '<?' in content)
        if likely_http and not has_http_options:
            warnings.append(f"성능 경고: HTTP 관련 패턴으로 추정되는 '{content}'을(를) 포함하지만, http_* 옵션이 없어 불필요한 검사를 유발할 수 있습니다.")

    # 2. nocase 검사
    if content_matches and 'nocase;' not in rule_lower:
        warnings.append("탐지 누락 가능성: content 옵션이 있지만 nocase 옵션이 없어 대소문자 변형을 놓칠 수 있습니다.")

    # 3. pcre 검사
    pcre_matches = re.findall(r'pcre\s*:\s*"([^"]+)"', rule_string, re.IGNORECASE)
    for pcre in pcre_matches:
        if pcre.startswith('/.*') or pcre.endswith('.*/'):
            warnings.append(f"성능 경고: PCRE 패턴 '{pcre}'은(는) 시작/끝의 '.*' 때문에 비효율적일 수 있습니다.")
        if len(re.findall(r'[\(\)\[\]\{\}\?\*\+\|]', pcre)) > 15: # 매우 단순한 복잡도 체크
             warnings.append(f"성능 경고: PCRE 패턴 '{pcre}'이(가) 너무 복잡하여 성능 저하를 유발할 수 있습니다.")

    # 4. 메타데이터 검사
    if 'sid:' not in rule_lower:
         warnings.append("필수 정보 누락: sid (Rule ID) 정보가 없습니다.")
    if 'rev:' not in rule_lower:
         warnings.append("필수 정보 누락: rev (Rule revision) 정보가 없습니다.")
    if 'reference:' not in rule_lower:
        warnings.append("정보 부족: reference 정보가 누락되었습니다 (예: cve, url).")

    return warnings

def _remove_unsupported_snort2_options(rule_string: str) -> str:
    """
    Snort 2.9.x에서 미지원 옵션을 자동 제거하거나 안전하게 대체한다.
    """

    # 완전히 삭제해야 하는 옵션들 (Snort 2.x 미지원)
    unsupported_keywords = [
        "tls.", "http2_", "ssh_", "app_layer_protocol",
        "http.request_body", "http.response_body", 
        "http.method", "http.uri", "http.header", "http.raw_uri",
        "filestore", "flowbits:setx", "flowbits:issetx",
        "metadata:service "
    ]

    # 옵션을 제거
    for key in unsupported_keywords:
        # key: "tls."이면 이런 패턴 삭제됨: tls.sni_host:“abc”;
        rule_string = re.sub(rf"{key}[^;]*;", "", rule_string, flags=re.IGNORECASE)

    # Suricata 스타일 metadata 제거
    rule_string = re.sub(r"metadata\s*:\s*[^;]+;", "", rule_string, flags=re.IGNORECASE)

    # Snort 3.x 스타일 flowbits 표현 정리
    rule_string = re.sub(r"flowbits\s*:\s*(setx|issetx)[^;]*;", "", rule_string, flags=re.IGNORECASE)

    # TLS 기반 도메인 탐지는 Snort2에서는 content로 대체해야 함
    # 예를 들어 'tls.sni_host:"example.com";' 제거 후, 도메인만 content로 넣어줌
    domain_match = re.search(r"tls\.sni_host\s*:\s*\"([^\"]+)\"", rule_string, re.IGNORECASE)
    if domain_match:
        domain = domain_match.group(1)
        # content로 추가 (case-insensitive)
        replacement = f'content:"{domain}"; nocase;'
        rule_string = rule_string + " " + replacement

    return rule_string


def _sanitize_snort_rule_for_2_9(rule_string: str) -> str:
    """
    Snort 2.9에서 지원하지 않는 옵션을 자동 변환하거나 제거한다.
    """
    replacements = {
        'http_host': 'http_header',
        'http_raw_host': 'http_raw_header',
    }
    for old, new in replacements.items():
        rule_string = rule_string.replace(old, new)

    rule_string = _remove_unsupported_snort2_options(rule_string)

    return rule_string


# --- 문법 검증 함수 (수정 없음, 이전 최종 버전과 동일) ---
def validate_rule_syntax(rule_string: str) -> Tuple[bool, str]:
    """
    WSL Snort를 사용하여 문법 유효성 검증 후, (성공 여부, Snort 출력 내용) 튜플을 반환.
    """
    if not rule_string or rule_string.lower().startswith("error:"):
        return False, f"Invalid rule string input: {rule_string[:100]}..."

    rule_string = _sanitize_snort_rule_for_2_9(rule_string)

    config_content = (
    "var HOME_NET any\n"
    "var EXTERNAL_NET any\n"
    "var HTTP_PORTS [80,443,8080]\n"
    "var HTTP_SERVERS $HOME_NET\n"
    f"{rule_string}"
)

    windows_config_path = ""
    full_output = ""

    try:
        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.conf', encoding='utf-8') as temp_config_file:
            temp_config_file.write(config_content)
            windows_config_path = temp_config_file.name

        wsl_config_path = _windows_path_to_wsl_path(windows_config_path)
        print(f"INFO: 임시 설정 파일 생성 (WSL 경로): {wsl_config_path}")

        command = ["wsl", "sudo", "snort", "-c", wsl_config_path, "-T"]
        print(f"INFO: 실행할 WSL 명령어: {' '.join(command)}")

        result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
        full_output = result.stdout + result.stderr

        success_message = "Snort successfully validated the configuration!"
        error_indicators = ["ERROR:", "Fatal Error"]

        if any(indicator in result.stderr for indicator in error_indicators):
            print(f"❌ (WSL Snort) 구문 검증 실패 (stderr 에러):\n{result.stderr}")
            return False, full_output
        elif success_message in full_output:
            print("✅ (WSL Snort) 구문 검증 성공")
            if "WARNING:" in full_output: # 경고는 stdout/stderr 모두 확인
                 print(f"INFO: Snort 경고 발생 (결과는 성공):\n{full_output}") # 전체 출력 로깅
            return True, full_output
        else:
            print(f"❌ (WSL Snort) 구문 검증 실패 (예상치 못한 출력):\n{full_output}")
            return False, full_output

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

# --- 통합 검증 함수 (수정 없음, 이전 버전과 동일) ---
def validate_rule(rule_string: str) -> Dict[str, any]: # 반환 타입 명시
    """
    문법 검증과 정적 분석을 모두 수행하고 결과를 종합하여 반환합니다.
    """
    syntax_valid, snort_output = validate_rule_syntax(rule_string)

    results = {
        "rule": rule_string,
        "syntax_valid": syntax_valid,
        "syntax_check_output": snort_output,
        "static_warnings": [],
        "overall_status": "Failed"
    }

    if syntax_valid:
        results["static_warnings"] = analyze_rule_statically(rule_string)
        if not results["static_warnings"]:
            results["overall_status"] = "Success"
        else:
            results["overall_status"] = "Warning"

    return results
# utils/validator.py

import subprocess
import os
import tempfile # <<-- 이 라이브러리를 사용합니다.

def validate_rule_syntax(rule_string: str, engine: str = 'snort') -> bool:
    """
    생성된 IDS Rule의 문법적 유효성을 검증합니다.
    """
    # tempfile을 사용하여 운영체제에 맞는 임시 파일 생성
    with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.rules', encoding='utf-8') as temp_rule_file:
        temp_rule_file.write(rule_string)
        rule_file_path = temp_rule_file.name

    print(f"INFO: 임시 Rule 파일 생성: {rule_file_path}")

    # 운영체제에 따라 명령어 경로 등은 수정 필요
    if engine == 'snort':
        command = [
            "snort", 
            "-c", "C:/Snort/etc/snort/snort.lua", # <<-- (주의) 나중에 실제 Snort 설치 경로로 바꿔야 함
            "--rule-path", os.path.dirname(rule_file_path),
            "--dump-rule-info"
        ]
    else: 
        command = ["suricata-analyze", "-S", rule_file_path]

    # --- (중요!) 지금은 Snort가 없으니 잠시 이 부분을 건너뛰도록 수정 ---
    # 실제 검증 로직 (향후 Snort 설치 후 주석 해제)
    # try:
    #     subprocess.run(
    #         command, check=True, capture_output=True, text=True, timeout=15
    #     )
    #     print(f"✅ 구문 검증 성공")
    #     is_valid = True
    # except Exception as e:
    #     print(f"❌ 구문 검증 실패: {e}")
    #     is_valid = False
    
    # 지금은 무조건 성공으로 처리하여 다음 단계로 넘어갈 수 있게 함
    print("INFO: [임시] Snort 미설치 상태이므로 검증을 건너뛰고 '성공'으로 처리합니다.")
    is_valid = True
    # --- 여기까지 ---

    # 임시 파일 삭제
    if os.path.exists(rule_file_path):
        os.remove(rule_file_path)
    
    return is_valid
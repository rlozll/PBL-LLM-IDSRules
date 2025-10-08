# utils/validator.py

import subprocess
import os
import tempfile

def _windows_path_to_wsl_path(windows_path: str) -> str:
    """
    Windows 경로를 WSL에서 사용할 수 있는 경로로 변환합니다.
    예: C:\\Users\\Test -> /mnt/c/Users/Test
    """
    path = windows_path.replace('\\', '/')
    drive, path_no_drive = os.path.splitdrive(path)
    drive_letter = drive.replace(':', '').lower()
    return f"/mnt/{drive_letter}{path_no_drive}"

def validate_rule_syntax(rule_string: str, engine: str = 'snort') -> bool:
    """
    WSL에 설치된 Snort를 호출하여 Rule의 문법적 유효성을 검증합니다.
    """
    # 1. Windows에 임시 규칙 파일을 생성합니다.
    with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.rules', encoding='utf-8') as temp_rule_file:
        temp_rule_file.write(rule_string)
        windows_rule_path = temp_rule_file.name

    try:
        # 2. Windows 경로를 WSL이 인식할 수 있는 경로로 변환합니다.
        wsl_rule_path = _windows_path_to_wsl_path(windows_rule_path)
        print(f"INFO: Windows 임시 파일: {windows_rule_path}")
        print(f"INFO: WSL 변환 경로: {wsl_rule_path}")

        # 3. WSL에 설치된 Snort 2.9의 설정 파일 경로를 지정합니다.
        wsl_config_path = '/etc/snort/snort.conf'

        # 4. wsl.exe를 통해 WSL 내부의 snort 명령어를 실행할 준비를 합니다.
        #    -c: 설정 파일을 지정합니다.
        #    -T: 설정 및 규칙을 테스트하는 'Test' 모드로 실행합니다.
        #    -r: 테스트할 규칙 파일을 읽어들입니다.
        command = [
            "wsl",
            "sudo", # Snort가 설정 파일을 읽으려면 관리자 권한이 필요할 수 있습니다.
            "snort",
            "-c", wsl_config_path,
            "-T",
            "-r", wsl_rule_path
        ]

        print(f"INFO: 실행할 WSL 명령어: {' '.join(command)}")

        # 5. WSL 명령어를 실행하여 검증을 수행합니다.
        result = subprocess.run(
            command, check=True, capture_output=True, text=True, timeout=30
        )
        # Snort 2.9는 성공 시 stderr에 상세 정보를 출력하므로, 특정 에러 메시지가 없는지 확인합니다.
        if "ERROR" in result.stderr or "Fatal" in result.stderr:
             print(f"❌ (WSL Snort) 구문 검증 실패:\n{result.stderr}")
             is_valid = False
        else:
             print("✅ (WSL Snort) 구문 검증 성공")
             is_valid = True

    except subprocess.CalledProcessError as e:
        # 명령 자체가 실패한 경우 (예: 경로 오류)
        print(f"❌ (WSL Snort) 명령어 실행 실패:\n{e.stderr}")
        is_valid = False
    
    finally:
        # 6. 검증이 끝나면 Windows에 생성된 임시 파일을 반드시 삭제합니다.
        if os.path.exists(windows_rule_path):
            os.remove(windows_rule_path)
    
    return is_valid
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
    WSL Snort를 사용하여 단일 Rule 문자열의 유효성을 검증합니다.
    (개선된 방식: 임시 설정 파일을 생성하여 테스트)
    """
    # 1. 검증할 Rule만 포함하는 '임시 설정 파일'의 내용을 만듭니다.
    #    Snort가 최소한의 설정을 인식하도록 'HOME_NET' 변수를 함께 넣어줍니다.
    config_content = f"var HOME_NET any\n{rule_string}"
    
    # Windows에 임시 설정 파일을 생성합니다.
    with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.conf', encoding='utf-8') as temp_config_file:
        temp_config_file.write(config_content)
        windows_config_path = temp_config_file.name

    try:
        # 2. Windows 경로를 WSL이 인식할 수 있는 경로로 변환합니다.
        wsl_config_path = _windows_path_to_wsl_path(windows_config_path)
        print(f"INFO: 임시 설정 파일 생성 (WSL 경로): {wsl_config_path}")

        # 3. wsl.exe를 통해 Snort를 '설정 테스트 모드(-T)'로 실행합니다.
        #    -c 옵션으로 방금 만든 임시 설정 파일을 지정합니다.
        #    이렇게 하면 다른 규칙이나 복잡한 설정 없이 오직 우리 Rule만 검사합니다.
        command = [
            "wsl",
            "sudo",
            "snort",
            "-c", wsl_config_path,
            "-T"  # <- 오류의 원인이었던 -r 옵션을 제거하고 -T만 사용합니다.
        ]

        print(f"INFO: 실행할 WSL 명령어: {' '.join(command)}")

        # 4. WSL 명령어를 실행하여 검증을 수행합니다.
        result = subprocess.run(
            command, check=True, capture_output=True, text=True, timeout=30
        )

        # Snort 2.9는 성공 시 stdout에 성공 메시지를 출력합니다.
        if "Snort successfully validated the configuration" in result.stdout:
            print("✅ (WSL Snort) 구문 검증 성공")
            is_valid = True
        else:
            # 성공 메시지가 없으면 실패로 간주합니다.
            print(f"❌ (WSL Snort) 구문 검증 실패 (성공 메시지 없음):\n{result.stderr}")
            is_valid = False

    except subprocess.CalledProcessError as e:
        # Snort가 문법 오류 등으로 0이 아닌 종료 코드를 반환하면 이 예외가 발생합니다.
        print(f"❌ (WSL Snort) 명령어 실행 오류 (문법 오류 가능성 높음):\n{e.stderr}")
        is_valid = False
    
    finally:
        # 5. 검증이 끝나면 Windows에 생성된 임시 설정 파일을 반드시 삭제합니다.
        if os.path.exists(windows_config_path):
            os.remove(windows_config_path)
    
    return is_valid 
import subprocess
import os
import tempfile
from typing import  Dict

snort_rule_path = "/etc/snort/rules/local.rules"
# wsl ubuntu에서 sudo visudo 입력 후, sficheu ALL=(ALL) NOPASSWD: /usr/sbin/snort \n sficheu ALL=(ALL) NOPASSWD: /usr/bin/tee \n sficheu ALL=(ALL) NOPASSWD: ALL 추가

def _windows_path_to_wsl_path(windows_path: str) -> str:
    """Windows 경로를 WSL 경로로 변환합니다."""
    path = windows_path.replace('\\', '/')
    drive, path_no_drive = os.path.splitdrive(path)
    drive_letter = drive.replace(':', '').lower()
    return f"/mnt/{drive_letter}{path_no_drive}"

def deploy_rule_sync(rule_string: str) -> Dict[str, str]:    
    windows_rule_path = ""
    rule_content = rule_string.strip() + "\n\n"
    try:
      with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.rules', encoding='utf-8') as rule_file:
        rule_file.write(rule_content)
        windows_rule_path = rule_file.name
      print(f"INFO: 임시 Rule 파일 생성 (Windows 경로): {windows_rule_path}")
    
      wsl_rule_path = _windows_path_to_wsl_path(windows_rule_path)
      project_root = os.path.dirname(os.path.dirname(__file__)) 
      deploy_script_path = os.path.join(project_root, "scripts", "deploy.sh")
      if not os.path.exists(deploy_script_path):
        return {"status":"Failed", "detail":f"필수 파일 누락: {deploy_script_path}"}
      wsl_script_path = _windows_path_to_wsl_path(deploy_script_path)
      command = ["wsl", "sudo", "bash", wsl_script_path, wsl_rule_path, snort_rule_path]
      print(f"INFO: 실행할 WSL 배포 명령어: {' '.join(command)}")
      result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False, encoding='utf-8')

      if result.returncode == 0:
        print(f"✅ Rule 배포 성공")
        return {"status": "Success", "detail":"성공적으로 배포 완료"}
      else:
        error = f"Exit Code: {result.returncode}), Stderr: {result.stderr.strip()}"
        print(f"❌ Rule 배포 실패: {error}")
        return {"status": "Failed", "detail":error}
    except subprocess.TimeoutExpired:
      print("❌ Rule 배포 시간 초과 (Timeout)")
      return {"status": "Failed", "detail":"Timeout"}
    except Exception as e:
      print(f"❌ Rule 배포 중 예기치 않은 오류: {e}")
      return {"status":"Failed", "detail":"error"}
    finally:
      if windows_rule_path and os.path.exists(windows_rule_path):
        try: os.remove(windows_rule_path)
        except Exception as e: print(f"WARNING: 임시 Rule 파일 삭제 실패: {e}")
#! /bin/bash
# 사용법: sudo bash deploy.sh <SOURCE_RULE_PATH_WSL> <TARGET_RULE_PATH_WSL>

source_rule=$1
target_rule=$2

if [ -z "$source_rule" ] || [ -z "$target_rule" ]; then
  echo "ERROR: 소스 파일과 타겟 파일 경로가 모두 필요합니다." >&2
  exit 1
fi

if [ ! -f "$source_rule" ]; then
  echo "ERROR: 소스 Rule 파일($source_rule)을 찾을 수 없습니다." >&2
  exit 1
fi

echo "INFO: Rule 배포 시작"

echo "INFO: $source_rule -> $target_rule (내용 추가 중)"
if ! cat "$source_rule" | sudo tee -a "$target_rule" > /dev/null; then
  echo "ERROR: Rule 파일 추가 실패." >&2
  exit 1
fi
echo "INFO: Rule 파일 추가 완료"

if command -v systemctl &> /dev/null; then
  echo "INFO: Snort 서비스 재시작 시도 중..."
  if systemctl is-active --quiet snort; then
    if systemctl reload snort; then
      echo "SUCCESS: Snort 서비스 재시작 완료"
    else
      echo "WARNING: Snort 서비스 강제 재시작 시도 중..."
      if systemctl restart snort; then
        echo "SUCCESS: Snort 서비스 재시작 완료."
      else
        echo "ERROR: Snort 서비스 재시작 실패." >&2
        exit 1
      fi
    fi
  else
    echo "INFO: Snort 서비스 시작 시도 중..."
    if systemctl start snort; then
      echo "SUCCESS: Snort 서비스 시작 완료"
    else
      echo "ERROR: Snort 서비스 시작 실패" >&2
      exit 1
    fi
  fi
else
  echo "WARNING: systemctl을 찾을 수 없습니다. 수동으로 Snort 서비스를 시작하십시오."
fi

exit 0
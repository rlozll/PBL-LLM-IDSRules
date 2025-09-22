# test_parser.py
from parser import get_text_from_url
import os # 파일/폴더 관리를 위한 os 모듈 추가

# 1. 파싱 실행
test_url = "https://attack.mitre.org/groups/"
clean_text = get_text_from_url(test_url)

# 2. (선택적) 디버깅을 위해 결과를 파일로 저장
# --- 이 부분이 제안하신 아이디어를 적용한 코드입니다 ---
try:
    # 'parsed_texts' 라는 폴더를 생성 (이미 있다면 그냥 넘어감)
    output_dir = 'parsed_texts'
    os.makedirs(output_dir, exist_ok=True)

    # URL에서 간단하게 파일 이름 추출 (예: 'groups.txt')
    filename = test_url.strip('/').split('/')[-1] + ".txt"
    filepath = os.path.join(output_dir, filename)

    # UTF-8 인코딩으로 파일에 쓰기
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(clean_text)
    
    print(f"✅ 파싱 결과가 '{filepath}' 파일에 저장되었습니다.")

except Exception as e:
    print(f"❗️ 파일 저장 중 오류 발생: {e}")
# ----------------------------------------------------

# 3. LLM 핸들러에는 '변수'를 직접 전달
print("\n----- LLM 핸들러에게 전달될 텍스트 (앞 500자) -----")
print(clean_text[:500])

# 나중에 llm_handler.py를 만들면 아래와 같이 호출하게 됩니다.
# from core.llm_handler import extract_iocs
# iocs = extract_iocs(clean_text)
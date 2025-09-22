# test_parser.py

from parser import get_text_from_url, crawl_zdi_blog_index
import os

# 1단계: 블로그 목록 페이지에서 모든 기사 URL을 수집
zdi_blog_url = "https://www.zerodayinitiative.com/blog/"
print(f"'{zdi_blog_url}' 에서 기사 목록 크롤링 시작...")
article_links = crawl_zdi_blog_index(zdi_blog_url)
print(f"총 {len(article_links)}개의 기사 링크를 찾았습니다.")

# 2단계: 수집된 링크들을 순회하며 각 페이지의 본문 파싱 (테스트를 위해 3개만 실행)
for i, link in enumerate(article_links[:3]): # 최신 3개 기사만 테스트
    print(f"\n===== {i+1}번째 기사 파싱 시작: {link} =====")
    
    # 각 기사 링크에 대해 본문 추출 함수 호출
    content = get_text_from_url(link)
    
    print(content[:500] + "...") # 내용이 너무 기니 500자만 미리보기
    
    # (선택적) 파일로 저장하는 로직
    output_dir = 'parsed_texts'
    os.makedirs(output_dir, exist_ok=True)
    filename = link.strip('/').split('/')[-1] + ".txt"
    filepath = os.path.join(output_dir, filename)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"✅ 파싱 결과가 '{filepath}' 파일에 저장되었습니다.")
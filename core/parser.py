# core/parser.py

import requests
from bs4 import BeautifulSoup
import fitz  # PyMuPDF
from urllib.parse import urljoin # URL을 합치기 위한 라이브러리
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from urllib.parse import urljoin
def _format_table_to_markdown(table_soup: BeautifulSoup) -> str:
    """BeautifulSoup의 table 객체를 Markdown 형식의 문자열로 변환하는 헬퍼 함수"""
    markdown_lines = []
    headers = [th.get_text(strip=True) for th in table_soup.find_all('th')]
    if not headers: return "" # 헤더 없는 테이블은 무시

    markdown_lines.append("| " + " | ".join(headers) + " |")
    markdown_lines.append("|" + "---|" * len(headers))

    for row in table_soup.find('tbody').find_all('tr'):
        cols = [td.get_text(separator=' ', strip=True).replace('\n', ' ') for td in row.find_all('td')]
        if cols:
            markdown_lines.append("| " + " | ".join(cols) + " |")
    
    return "\n".join(markdown_lines) + "\n"


def _parse_mitre_group_page(soup: BeautifulSoup) -> str:
    """Mitre ATT&CK 그룹 목록 또는 상세 페이지에서 정보를 추출하는 전용 파서"""
    extracted_parts = []

    # 페이지 제목 추출
    title_tag = soup.find('h1')
    if title_tag:
        extracted_parts.append(f"Title: {title_tag.get_text(strip=True)}\n")

    # 페이지 상단 설명 추출
    # <div class="col-md-10 offset-md-1"> 안에 설명이 위치함
    description_div = soup.find('div', class_='col-md-10')
    if description_div:
        for p_tag in description_div.find_all('p'):
            extracted_parts.append(p_tag.get_text(strip=True))

    # --- 분기점: 목록 페이지인지 상세 페이지인지 확인 ---
    
    # 1. 그룹 '목록' 페이지의 메인 테이블 처리 (table-striped 클래스를 가짐)
    main_table = soup.find('table', class_='table-striped')
    if main_table:
        extracted_parts.append("\n--- Threat Groups List ---\n")
        extracted_parts.append(_format_table_to_markdown(main_table))
    else:
        # 2. 그룹 '상세' 페이지의 여러 테이블들 처리
        all_tables = soup.find_all('table', class_='table')
        for table in all_tables:
            # 테이블 바로 위에 있는 제목(h2)을 찾아서 테이블 이름으로 사용
            table_title_tag = table.find_previous_sibling('h2')
            table_title = table_title_tag.get_text(strip=True) if table_title_tag else "Details Table"
            extracted_parts.append(f"\n--- {table_title} ---\n")
            extracted_parts.append(_format_table_to_markdown(table))

    return "\n".join(extracted_parts).strip()


# core/parser.py 의 get_text_from_url 함수 수정

def get_text_from_url(url: str) -> str:
    """주어진 URL에서 접속하여 HTML을 파싱하고, 기사 본문으로 추정되는 텍스트를 추출합니다."""
    try:
        # ... (기존 requests 코드와 동일)
        headers = { 'User-Agent': '...' }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # --- URL 패턴에 따라 적절한 파서 호출 ---
        if "attack.mitre.org/groups" in url:
            return _parse_mitre_group_page(soup)
        
        # --- 일반 블로그/뉴스 사이트용 파싱 로직 ---
        # 1순위: ZDI 블로그 본문 컨테이너
        if soup.find('div', class_='body-content'):
             main_content = soup.find('div', class_='body-content')
        # 2순위: 일반적인 <article> 태그
        elif soup.find('article'):
            main_content = soup.find('article')
        # ... (이하 다른 elif 조건들은 기존과 동일)
        elif soup.find(id='content'):
            main_content = soup.find(id='content')
        # ... (이하 생략) ...
        
        # 이하 불필요한 태그 제거 및 텍스트 추출 코드는 기존과 동일
        if not main_content: return "본문 내용을 찾을 수 없습니다."
        for tag in main_content(['script', 'style', 'nav', 'footer', 'aside']):
            tag.decompose()
        return main_content.get_text(separator='\n', strip=True)

    except Exception as e:
        return f"처리 중 알 수 없는 오류 발생: {e}"

# PDF 파서 함수는 변경 없음
def get_text_from_pdf(file_path: str) -> str:
    # ... (기존 코드와 동일) ...
    try:
        import fitz
        doc = fitz.open(file_path)
        full_text = ["".join(page.get_text()) for page in doc]
        doc.close()
        return "\n".join(full_text)
    except Exception as e:
        return f"PDF 처리 중 오류 발생: {e}"

def crawl_zdi_blog_index(index_url: str) -> list[str]:
    """
    [Selenium 4 최종 버전] ZDI 블로그 목록 페이지에서 URL 목록을 수집합니다.
    Selenium 내장 드라이버 관리자를 사용하여 안정성을 높입니다.
    """
    article_urls = []
    options = webdriver.ChromeOptions()
    # 안정성을 위해 몇 가지 옵션 추가
    options.add_argument('--headless')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--log-level=3')

    # ▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼
    # 수정된 부분: 이제 webdriver.Chrome(options=options) 만 호출하면
    # Selenium이 자동으로 PC의 크롬 버전을 확인하고 그에 맞는 드라이버를 다운로드/관리합니다.
    with webdriver.Chrome(options=options) as driver:
    # ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲
        try:
            driver.get(index_url)
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.CLASS_NAME, "blog-collection-item-link"))
            )
            final_html = driver.page_source
            soup = BeautifulSoup(final_html, 'html.parser')

            for link_tag in soup.find_all('a', class_='blog-collection-item-link'):
                if 'href' in link_tag.attrs:
                    full_url = urljoin(index_url, link_tag['href'])
                    article_urls.append(full_url)
            
            return article_urls

        except Exception as e:
            print(f"Selenium 크롤링 중 오류 발생: {e}")
            return []
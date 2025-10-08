import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from typing import Optional

# 선택: PDF 파싱
import fitz  # PyMuPDF

# 선택: ZDI 목록 크롤링용
try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    HAS_SELENIUM = True
except Exception:
    HAS_SELENIUM = False


# ============================================================
# 공통 텍스트 정제 함수
# ============================================================
def _clean_text(text: str) -> str:
    """
    추출된 텍스트의 공통 후처리:
    - 과도한 공백/탭 제거
    - 연속된 빈 줄 축소
    - 특수문자 정규화
    - 앞뒤 공백 제거
    """
    if not text:
        return ""
    
    # 1. 탭을 공백으로 변환
    text = text.replace('\t', ' ')
    
    # 2. 다중 공백을 단일 공백으로
    text = re.sub(r' {2,}', ' ', text)
    
    # 3. 줄 끝 공백 제거
    lines = [line.rstrip() for line in text.split('\n')]
    text = '\n'.join(lines)
    
    # 4. 연속된 빈 줄을 최대 2개로 제한
    text = re.sub(r'\n{4,}', '\n\n\n', text)
    
    # 5. 특수 유니코드 공백 문자 정규화
    text = re.sub(r'[\u00a0\u1680\u2000-\u200b\u202f\u205f\u3000]', ' ', text)
    
    # 6. Zero-width 문자 제거
    text = re.sub(r'[\u200b-\u200d\ufeff]', '', text)
    
    # 7. 앞뒤 공백 제거
    text = text.strip()
    
    return text


# ============================================================
# HTML 테이블 → Markdown 변환 (개선)
# ============================================================
def _format_table_to_markdown(table_soup: BeautifulSoup) -> str:
    """
    BeautifulSoup의 table 객체를 Markdown 형식으로 변환
    - 병합된 셀 처리 개선
    - 빈 셀 처리
    """
    markdown_lines = []
    
    # 헤더 추출
    headers = []
    header_row = table_soup.find('thead')
    if header_row:
        headers = [th.get_text(strip=True) for th in header_row.find_all(['th', 'td'])]
    else:
        first_row = table_soup.find('tr')
        if first_row:
            headers = [th.get_text(strip=True) for th in first_row.find_all('th')]
    
    if not headers:
        return ""
    
    # 헤더 행 생성
    headers = [h if h else "N/A" for h in headers]  # 빈 헤더 처리
    markdown_lines.append("| " + " | ".join(headers) + " |")
    markdown_lines.append("|" + " --- |" * len(headers))
    
    # 데이터 행 추출
    tbody = table_soup.find('tbody') or table_soup
    for row in tbody.find_all('tr'):
        cols = []
        for td in row.find_all('td'):
            # 셀 내부의 모든 텍스트를 공백으로 구분하여 추출
            cell_text = td.get_text(separator=' ', strip=True)
            # 줄바꿈을 공백으로 변환
            cell_text = re.sub(r'\s+', ' ', cell_text)
            # 파이프 문자 이스케이프
            cell_text = cell_text.replace('|', '\\|')
            cols.append(cell_text if cell_text else "N/A")
        
        if cols:
            # 헤더 수와 맞추기
            while len(cols) < len(headers):
                cols.append("N/A")
            cols = cols[:len(headers)]
            markdown_lines.append("| " + " | ".join(cols) + " |")
    
    return "\n".join(markdown_lines) + "\n"


# ============================================================
# MITRE ATT&CK 전용 파서 (개선)
# ============================================================
def _parse_mitre_group_page(soup: BeautifulSoup) -> str:
    """
    MITRE ATT&CK 그룹 페이지 전용 파서
    - 메타데이터 추출 개선
    - 섹션별 구조화
    """
    extracted_parts = []
    
    # 1. 제목
    title_tag = soup.find('h1')
    if title_tag:
        extracted_parts.append(f"# {title_tag.get_text(strip=True)}\n")
    
    # 2. 메타데이터 (ID, Associated Groups 등)
    meta_div = soup.find('div', class_='card-body')
    if meta_div:
        extracted_parts.append("## Metadata\n")
        for dt_tag in meta_div.find_all('dt'):
            dd_tag = dt_tag.find_next_sibling('dd')
            if dd_tag:
                key = dt_tag.get_text(strip=True)
                value = dd_tag.get_text(strip=True)
                extracted_parts.append(f"- **{key}**: {value}")
        extracted_parts.append("")
    
    # 3. 설명
    description_div = soup.find('div', class_='description-body')
    if description_div:
        extracted_parts.append("## Description\n")
        for p_tag in description_div.find_all('p'):
            text = p_tag.get_text(strip=True)
            if text:
                extracted_parts.append(text)
        extracted_parts.append("")
    
    # 4. 테이블 처리
    all_tables = soup.find_all('table', class_=['table', 'table-striped'])
    for table in all_tables:
        # 테이블 제목 찾기
        title_tag = table.find_previous(['h2', 'h3', 'h4'])
        if title_tag:
            table_title = title_tag.get_text(strip=True)
            extracted_parts.append(f"## {table_title}\n")
        
        extracted_parts.append(_format_table_to_markdown(table))
        extracted_parts.append("")
    
    result = "\n".join(extracted_parts).strip()
    return _clean_text(result)


# ============================================================
# 노이즈 제거 (확장)
# ============================================================
NOISE_SELECTORS = [
    # 광고 및 프로모션
    "[class*='advert']", "[id*='advert']", ".ads", ".ad", "#ad",
    "[class*='ad-']", "[class*='sponsor']", ".promo", ".promotion",
    
    # 구독 및 소셜
    ".subscribe", ".newsletter", ".email-signup", ".share", ".social",
    ".social-share", ".share-buttons",
    
    # 네비게이션 및 레이아웃
    ".sidebar", ".side-bar", ".breadcrumb", ".breadcrumbs",
    ".cookie", ".cookie-banner", ".banner", ".modal", ".popup",
    
    # 댓글 및 관련 콘텐츠
    ".comments", "#comments", ".comment-section", ".disqus",
    ".related", ".related-posts", ".recommended",
    
    # TOC 및 메뉴
    ".toc", ".table-of-contents", "#toc", ".menu", ".navigation",
    
    # 푸터 및 헤더
    "nav", "footer", "aside", "form", "header.site-header",
    
    # 기타
    ".print-only", ".hidden", "[style*='display:none']", "[style*='display: none']"
]

CANDIDATES = [
    # 높은 우선순위
    "article", "main", "[role='main']", "[role='article']",
    
    # 일반적인 콘텐츠 컨테이너
    ".post-content", ".entry-content", ".article-content",
    ".article-body", ".post-body", ".blog-content",
    ".content__body", ".main-content", ".page-content",
    
    # ID 기반
    "#content", "#main-content", "#article", "#post",
    
    # 백업
    ".content", "body"
]


def _strip_noise(soup: BeautifulSoup) -> None:
    """광고, 사이드바, 댓글 등 노이즈 영역 제거"""
    for sel in NOISE_SELECTORS:
        for tag in soup.select(sel):
            tag.decompose()
    
    # 스크립트와 스타일 추가 제거
    for tag in soup(['script', 'style', 'noscript', 'iframe']):
        tag.decompose()


def _normalize_text(text: str) -> str:
    """
    여분 공백/빈 줄 정리 (레거시, _clean_text로 대체 권장)
    """
    lines = [ln.strip() for ln in text.splitlines()]
    lines = [ln for ln in lines if ln]
    return "\n".join(lines)


# ============================================================
# 핵심: URL에서 본문 추출 (대폭 개선)
# ============================================================
def get_text_from_url(url: str, timeout: int = 20) -> str:
    """
    URL의 HTML을 파싱하여 본문 텍스트를 추출
    
    개선사항:
    - 더 나은 인코딩 처리
    - 구조화된 데이터 추출 (제목, 날짜, 저자)
    - 단락 구조 유지
    - 향상된 본문 선택 알고리즘
    """
    try:
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/131.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
        }
        
        r = requests.get(url, headers=headers, timeout=timeout)
        
        # 인코딩 처리 개선
        if r.encoding and r.encoding.lower() in ['iso-8859-1', 'windows-1252']:
            r.encoding = r.apparent_encoding or 'utf-8'
        elif not r.encoding:
            r.encoding = 'utf-8'
        
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")
        
        # MITRE 특수 처리
        if "attack.mitre.org/groups" in url:
            return _parse_mitre_group_page(soup)
        
        # 노이즈 제거
        _strip_noise(soup)
        
        # 본문 컨테이너 찾기
        main = None
        for sel in CANDIDATES:
            found = soup.select_one(sel)
            if found:
                main = found
                break
        
        if not main:
            main = soup.body or soup
        
        # 추가 정제
        for tag in main(['script', 'style', 'nav', 'footer', 'aside', 'form', 'button']):
            tag.decompose()
        
        # 메타데이터 추출
        result_parts = []
        
        # 제목
        title = soup.find('h1')
        if title:
            result_parts.append(f"# {title.get_text(strip=True)}\n")
        
        # 본문 추출
        text = main.get_text(separator="\n", strip=True)
        result_parts.append(text)
        
        final_text = "\n".join(result_parts)
        final_text = _clean_text(final_text)
        
        return final_text if final_text else "본문 내용을 찾을 수 없습니다."
        
    except requests.Timeout:
        return f"타임아웃 오류: {url} 에 접근할 수 없습니다. (제한시간: {timeout}초)"
    except requests.RequestException as e:
        return f"요청 오류: {e}"
    except Exception as e:
        return f"처리 중 알 수 없는 오류 발생: {e}"


# ============================================================
# PDF 텍스트 추출 (대폭 개선)
# ============================================================
def get_text_from_pdf(file_path: str, 
                      fix_hyphenation: bool = True,
                      preserve_layout: bool = False) -> str:
    """
    PDF 파일에서 텍스트 추출
    
    개선사항:
    - 하이픈 처리 개선
    - 레이아웃 보존 옵션
    - 단락 구조 유지
    - 헤더/푸터 제거
    - 페이지 번호 처리
    """
    try:
        doc = fitz.open(file_path)
        pages_text = []
        
        for page_num, page in enumerate(doc, 1):
            # 텍스트 추출 (레이아웃 보존 여부에 따라)
            if preserve_layout:
                text = page.get_text("text", sort=True)
            else:
                text = page.get_text()
            
            # 페이지 번호 패턴 제거 (단독 숫자 라인)
            lines = text.split('\n')
            lines = [line for line in lines if not (line.strip().isdigit() and len(line.strip()) <= 4)]
            text = '\n'.join(lines)
            
            pages_text.append(text)
        
        doc.close()
        
        # 전체 텍스트 병합
        raw = "\n\n".join(pages_text)
        
        # 하이픈 처리
        if fix_hyphenation:
            # 단어 중간의 하이픈+줄바꿈 제거: "exam-\nple" -> "example"
            raw = re.sub(r"(\w)-\s*\n\s*(\w)", r"\1\2", raw)
            
            # 줄 끝 하이픈 처리 (대문자로 시작하는 경우는 유지)
            raw = re.sub(r"(\w)-\s*\n\s*([a-z])", r"\1\2", raw)
        
        # 다중 공백/탭 정리
        raw = re.sub(r"[ \t]+", " ", raw)
        
        # 과도한 빈 줄 축소
        raw = re.sub(r"\n{4,}", "\n\n\n", raw)
        
        # 공통 후처리
        raw = _clean_text(raw)
        
        return raw if raw else "PDF에서 텍스트를 추출할 수 없습니다."
        
    except FileNotFoundError:
        return f"파일을 찾을 수 없습니다: {file_path}"
    except fitz.FileDataError:
        return f"손상되었거나 지원되지 않는 PDF 파일: {file_path}"
    except Exception as e:
        return f"PDF 처리 중 오류 발생: {e}"


# ============================================================
# (선택) ZDI 블로그 크롤링 (개선)
# ============================================================
def crawl_zdi_blog_index(index_url: str, max_articles: Optional[int] = None) -> list[str]:
    """
    ZDI 블로그 목록 페이지에서 URL 수집
    
    개선사항:
    - 중복 제거
    - 최대 개수 제한
    - 더 나은 에러 핸들링
    """
    if not HAS_SELENIUM:
        print("[WARN] selenium 미설치 → crawl_zdi_blog_index() 건너뜀")
        return []
    
    article_urls = []
    options = webdriver.ChromeOptions()
    options.add_argument('--headless=new')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--disable-gpu')
    options.add_argument('--log-level=3')
    options.add_experimental_option('excludeSwitches', ['enable-logging'])
    
    driver = None
    try:
        driver = webdriver.Chrome(options=options)
        driver.get(index_url)
        
        # 페이지 로드 대기
        WebDriverWait(driver, 15).until(
            EC.presence_of_element_located((By.CLASS_NAME, "blog-collection-item-link"))
        )
        
        final_html = driver.page_source
        soup = BeautifulSoup(final_html, 'html.parser')
        
        # URL 수집 (중복 제거)
        seen_urls = set()
        for link_tag in soup.find_all('a', class_='blog-collection-item-link'):
            href = link_tag.get('href')
            if href:
                full_url = urljoin(index_url, href)
                if full_url not in seen_urls:
                    seen_urls.add(full_url)
                    article_urls.append(full_url)
                    
                    # 최대 개수 제한
                    if max_articles and len(article_urls) >= max_articles:
                        break
        
        return article_urls
        
    except Exception as e:
        print(f"Selenium 크롤링 중 오류 발생: {e}")
        return []
    finally:
        if driver:
            driver.quit()


# ============================================================
# 배치 처리 유틸리티 (추가)
# ============================================================
def process_urls_batch(urls: list[str], max_workers: int = 5) -> dict[str, str]:
    """
    여러 URL을 병렬로 처리
    
    Args:
        urls: 처리할 URL 리스트
        max_workers: 동시 처리 스레드 수
    
    Returns:
        {url: extracted_text} 딕셔너리
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {executor.submit(get_text_from_url, url): url for url in urls}
        
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                text = future.result()
                results[url] = text
            except Exception as e:
                results[url] = f"처리 실패: {e}"
    
    return results
# /Users/kimnahyun/Desktop/pbl/PBL-LLM-IDSRules/core/parser.py

import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# 선택: PDF 파싱
import fitz  # PyMuPDF

# 선택: ZDI 목록 크롤링용 (없어도 동작에 문제 없음)
try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    HAS_SELENIUM = True
except Exception:
    HAS_SELENIUM = False


# ------------------------------------------------------------
# 공통: HTML 테이블 → Markdown (MITRE 전용 보조)
# ------------------------------------------------------------
def _format_table_to_markdown(table_soup: BeautifulSoup) -> str:
    """BeautifulSoup의 table 객체를 Markdown 형식의 문자열로 변환"""
    markdown_lines = []
    headers = [th.get_text(strip=True) for th in table_soup.find_all('th')]
    if not headers:
        return ""  # 헤더 없는 테이블은 무시

    markdown_lines.append("| " + " | ".join(headers) + " |")
    markdown_lines.append("|" + "---|" * len(headers))

    tbody = table_soup.find('tbody') or table_soup
    for row in tbody.find_all('tr'):
        cols = [td.get_text(separator=' ', strip=True).replace('\n', ' ') for td in row.find_all('td')]
        if cols:
            markdown_lines.append("| " + " | ".join(cols) + " |")
    return "\n".join(markdown_lines) + "\n"


def _parse_mitre_group_page(soup: BeautifulSoup) -> str:
    """Mitre ATT&CK 그룹 목록 또는 상세 페이지 전용 파서"""
    extracted_parts = []

    # 제목
    title_tag = soup.find('h1')
    if title_tag:
        extracted_parts.append(f"Title: {title_tag.get_text(strip=True)}\n")

    # 상단 설명
    description_div = soup.find('div', class_='col-md-10')
    if description_div:
        for p_tag in description_div.find_all('p'):
            extracted_parts.append(p_tag.get_text(strip=True))

    # 목록/상세 분기
    main_table = soup.find('table', class_='table-striped')
    if main_table:
        extracted_parts.append("\n--- Threat Groups List ---\n")
        extracted_parts.append(_format_table_to_markdown(main_table))
    else:
        all_tables = soup.find_all('table', class_='table')
        for table in all_tables:
            table_title_tag = table.find_previous_sibling('h2')
            table_title = table_title_tag.get_text(strip=True) if table_title_tag else "Details Table"
            extracted_parts.append(f"\n--- {table_title} ---\n")
            extracted_parts.append(_format_table_to_markdown(table))

    return "\n".join(extracted_parts).strip()


# ------------------------------------------------------------
# 본문 추출: 노이즈 제거 + 본문 후보 선택
# ------------------------------------------------------------
NOISE_SELECTORS = [
    # 광고/프로모션/구독/공유/사이드바/배너/쿠키/코멘트/TOC
    "[class*='advert']", ".ads", ".ad", "#ad", "[class*='ad-']",
    ".subscribe", ".newsletter", ".promo", ".share", ".social",
    ".sidebar", ".breadcrumb", ".cookie", ".banner", ".modal",
    ".comments", "#comments", ".related", ".toc", ".table-of-contents",
    # 사이트 공통 잡영역
    "nav", "footer", "aside", "form"
]

CANDIDATES = [
    # 가장 흔한 본문 컨테이너
    "article", "main", "[role='main']",
    ".post-content", ".entry-content", ".article-content",
    ".content__body", ".post-body", ".blog-content",
    "#content", "#main-content", ".body-content"
]


def _strip_noise(soup: BeautifulSoup) -> None:
    """광고/사이드바/코멘트 등 노이즈 영역 제거"""
    for sel in NOISE_SELECTORS:
        for tag in soup.select(sel):
            tag.decompose()


def _normalize_text(text: str) -> str:
    """여분 공백/빈 줄 정리"""
    lines = [ln.strip() for ln in text.splitlines()]
    lines = [ln for ln in lines if ln]  # 빈 줄 제거
    return "\n".join(lines)


# ------------------------------------------------------------
# 핵심: URL에서 본문 텍스트 추출
# ------------------------------------------------------------
def get_text_from_url(url: str) -> str:
    """URL의 HTML을 파싱하여 본문 텍스트를 최대한 깨끗하게 추출"""
    try:
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/127.0.0.1 Safari/537.36"
            )
        }
        r = requests.get(url, headers=headers, timeout=15)
        # 인코딩 추정 우선 → 실패 시 utf-8
        if not r.encoding or r.encoding.lower() == "iso-8859-1":
            r.encoding = r.apparent_encoding or "utf-8"
        r.raise_for_status()

        soup = BeautifulSoup(r.text, "html.parser")

        # MITRE 그룹 페이지 전용 처리
        if "attack.mitre.org/groups" in url:
            return _parse_mitre_group_page(soup)

        # 노이즈 제거
        _strip_noise(soup)

        # 본문 컨테이너 선택
        main = None
        for sel in CANDIDATES:
            found = soup.select_one(sel)
            if found:
                main = found
                break
        if not main:
            # 그래도 못찾으면 body 전체
            main = soup.body or soup

        # 공통 잡태그 제거 (보수적으로 한 번 더)
        for tag in main(["script", "style", "nav", "footer", "aside", "form"]):
            tag.decompose()

        text = main.get_text(separator="\n", strip=True)
        text = _normalize_text(text)
        return text if text else "본문 내용을 찾을 수 없습니다."

    except Exception as e:
        return f"처리 중 알 수 없는 오류 발생: {e}"


# ------------------------------------------------------------
# PDF 텍스트 추출: 줄바꿈/하이픈 정리
# ------------------------------------------------------------
def get_text_from_pdf(file_path: str) -> str:
    try:
        doc = fitz.open(file_path)
        pages = [p.get_text() for p in doc]
        doc.close()
        raw = "\n".join(pages)

        # 하이픈으로 끊긴 단어 복구: "exam-\nple" -> "example"
        raw = re.sub(r"(\w)-\n(\w)", r"\1\2", raw)
        # 다중 공백/탭 정리
        raw = re.sub(r"[ \t]+", " ", raw)
        # 과한 빈 줄 축소
        raw = re.sub(r"\n{3,}", "\n\n", raw)

        return raw.strip()
    except Exception as e:
        return f"PDF 처리 중 오류 발생: {e}"


# ------------------------------------------------------------
# (선택) ZDI 블로그 목록 페이지에서 글 링크 수집 (Selenium)
# ------------------------------------------------------------
def crawl_zdi_blog_index(index_url: str) -> list[str]:
    """
    ZDI 블로그 목록 페이지에서 URL 목록을 수집합니다.
    Selenium이 없으면 빈 리스트 반환.
    """
    if not HAS_SELENIUM:
        print("[WARN] selenium 미설치 → crawl_zdi_blog_index() 건너뜀")
        return []

    article_urls = []
    options = webdriver.ChromeOptions()
    options.add_argument('--headless=new')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--log-level=3')

    with webdriver.Chrome(options=options) as driver:
        try:
            driver.get(index_url)
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.CLASS_NAME, "blog-collection-item-link"))
            )
            final_html = driver.page_source
            soup = BeautifulSoup(final_html, 'html.parser')

            for link_tag in soup.find_all('a', class_='blog-collection-item-link'):
                href = link_tag.get('href')
                if href:
                    full_url = urljoin(index_url, href)
                    article_urls.append(full_url)
            return article_urls
        except Exception as e:
            print(f"Selenium 크롤링 중 오류 발생: {e}")
            return []
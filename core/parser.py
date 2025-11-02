# -*- coding: utf-8 -*-
"""
core/parser.py — CTI/보안 블로그 본문 추출기 (하이브리드 개선 버전)
- [New] Selenium Fallback: 'requests'가 실패하거나 JS 렌더링이 의심될 경우,
-         Selenium(Chrome)을 이용해 JS를 렌더링한 최종 HTML로 재시도합니다.
- [New] 로직 분리: HTML을 '가져오는(fetch)' 로직과 '파싱하는(parse)' 로직을 분리하여
-         requests/Selenium이 동일한 파싱 로직을 공유하도록 수정했습니다.
- (기존) PDF 자동 판별, MITRE/Cloudflare 최적화 등은 모두 유지됩니다.
"""

from __future__ import annotations
import re
import requests
from typing import Optional, List, Dict
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time
import fitz # PyMuPDF

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    HAS_SELENIUM = True
except Exception:
    HAS_SELENIUM = False
    print("[WARN] Selenium 라이브러리를 찾을 수 없습니다. 'pip install selenium'을 실행하면 JS 렌더링 사이트 분석이 가능해집니다.")


# ---------------------------
# 공통 정리 유틸
# ---------------------------
def _clean_text(text: str) -> str:
    """공백, 빈 줄, 특수문자 정리"""
    if not text:
        return ""
    text = text.replace("\t", " ")
    text = re.sub(r" {2,}", " ", text)
    # 라인 우측 공백 제거
    lines = [ln.rstrip() for ln in text.split("\n")]
    text = "\n".join(lines)
    # 과도한 연속 빈 줄 축소
    text = re.sub(r"\n{4,}", "\n\n\n", text)
    # 희귀 공백/제로폭 제거
    text = re.sub(r"[\u00a0\u1680\u2000-\u200b\u202f\u205f\u3000]", " ", text)
    text = re.sub(r"[\u200b-\u200d\ufeff]", "", text)
    return text.strip()


def _dedupe_neighbor_lines(text: str) -> str:
    """연속 중복 줄 제거"""
    if not text:
        return ""
    out, prev = [], None
    for ln in text.splitlines():
        if prev is not None and ln == prev:
            continue
        out.append(ln)
        prev = ln
    return "\n".join(out)


# ---------------------------
# 테이블 → Markdown (간단)
# ---------------------------
def _format_table_to_markdown(tb: BeautifulSoup) -> str:
    """HTML 테이블을 마크다운 테이블로 변환"""
    thead = tb.find("thead")
    if thead:
        headers = [th.get_text(strip=True) or "N/A" for th in thead.find_all(["th", "td"])]
    else:
        first_tr = tb.find("tr")
        headers = []
        if first_tr:
            ths = [th.get_text(strip=True) for th in first_tr.find_all("th")]
            if ths:
                headers = [h or "N/A" for h in ths]
            else:
                tds = first_tr.find_all("td")
                if tds:
                    headers = [f"Col{i+1}" for i in range(len(tds))]
    if not headers:
        return ""
    lines = []
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("|" + " --- |" * len(headers))
    body = tb.find("tbody") or tb
    for tr in body.find_all("tr"):
        tds = tr.find_all("td")
        if not tds:
            continue
        cells = [td.get_text(separator=" ", strip=True).replace("|", "\\|") for td in tds]
        if len(cells) < len(headers):
            cells += ["N/A"] * (len(headers) - len(cells))
        cells = cells[:len(headers)]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


# ---------------------------
# MITRE ATT&CK 파서
# ---------------------------
def _parse_mitre_group_page(soup: BeautifulSoup) -> str:
    """MITRE ATT&CK 그룹 페이지 전용 파서"""
    parts: List[str] = []
    h1 = soup.find("h1")
    if h1:
        parts.append(f"# {h1.get_text(strip=True)}\n")
    meta = soup.find("div", class_="card-body")
    if meta:
        parts.append("## Metadata")
        for dt in meta.find_all("dt"):
            dd = dt.find_next_sibling("dd")
            if dd:
                parts.append(f"- **{dt.get_text(strip=True)}**: {dd.get_text(strip=True)}")
        parts.append("")
    desc = soup.find("div", class_="description-body")
    if desc:
        parts.append("## Description")
        for p in desc.find_all("p"):
            t = p.get_text(strip=True)
            if t:
                parts.append(t)
        parts.append("")
    for tb in soup.find_all("table", class_=["table", "table-striped"]):
        ttitle = tb.find_previous(["h2", "h3", "h4"])
        if ttitle:
            parts.append(f"## {ttitle.get_text(strip=True)}\n")
        parts.append(_format_table_to_markdown(tb))
        parts.append("")
    out = _clean_text("\n".join(parts))
    return _dedupe_neighbor_lines(out)


# ---------------------------
# 노이즈 제거
# ---------------------------
NOISE_SELECTORS = [
    "[class*='advert']", "[id*='advert']", ".ads", ".ad", "#ad",
    "[class*='ad-']", "[class*='sponsor']", ".promo", ".promotion",
    ".subscribe", ".newsletter", ".email-signup", ".share", ".social",
    ".social-share", ".share-buttons",
    ".sidebar", ".side-bar", ".breadcrumb", ".breadcrumbs",
    ".cookie", ".cookie-banner", ".banner", ".modal", ".popup",
    ".comments", "#comments", ".comment-section", ".disqus",
    ".related", ".related-posts", ".recommended",
    ".toc", ".table-of-contents", "#toc", ".menu", ".navigation",
    "nav", "footer", "aside", "form", "header.site-header",
    ".print-only", ".hidden", "[style*='display:none']", "[style*='display: none']",
]
CANDIDATES = [
    "article", "main", "[role='main']", "[role='article']",
    ".post-content", ".entry-content", ".article-content",
    ".article-body", ".post-body", ".blog-content",
    ".content__body", ".main-content", ".page-content",
    "#content", "#main-content", "#article", "#post",
    ".content", "body"
]


def _strip_noise(soup: BeautifulSoup) -> None:
    """HTML에서 불필요한 태그들을 제거"""
    for sel in NOISE_SELECTORS:
        for tag in soup.select(sel):
            tag.decompose()
    for tag in soup(["script", "style", "noscript", "iframe"]):
        tag.decompose()


def _guess_main(soup: BeautifulSoup) -> BeautifulSoup:
    """본문일 가능성이 높은 컨테이너 추측"""
    for sel in CANDIDATES:
        found = soup.select_one(sel)
        if found:
            # 너무 짧은 컨테이너는 본문이 아닐 가능성이 높음 (예: 헤더의 <main>)
            if len(found.get_text(strip=True)) > 150:
                return found
    # 마땅한 후보가 없으면 body 태그 또는 soup 객체 자체 반환
    return soup.body or soup


# ---------------------------
# Cloudflare 전용 정리
# ---------------------------
def _drop_cloudflare_noise(root: BeautifulSoup) -> None:
    """Cloudflare 블로그의 특정 노이즈 제거"""
    # 구조적: 언어 선택/메타/TOC/공유
    selectors = [
        "header", ".post-meta", ".byline", ".language", ".languages",
        ".language-selector", ".toc", ".table-of-contents",
        ".ArticleMeta", ".PostSidebar", "nav[aria-label='Languages']",
        "ul[aria-label='Language selector']",
        ".share", ".social", ".social-share", ".subscribe", ".newsletter",
        ".breadcrumbs", ".breadcrumb",
    ]
    for sel in selectors:
        for t in root.select(sel):
            t.decompose()

    # 텍스트 패턴 기반 제거: ‘이 게시물은 … 이용할 수 있습니다’, ‘X분 읽기’
    patterns = [
        re.compile(r"^\s*\d+\s*분\s*읽기\s*$"),
        re.compile(r"이\s*게시물은.*로도\s*이용할\s*수\s*있습니다\.?"),
    ]
    for tag in list(root.find_all(text=True)):
        txt = tag.strip()
        if not txt:
            continue
        for pat in patterns:
            if pat.search(txt):
                # 전체 노드를 포함하는 가장 가까운 block 제거
                container = tag
                while container and container.parent and container.name not in ["p", "div", "section", "article"]:
                    container = container.parent
                (container or tag).extract()
                break


# ---------------------------
# PDF 처리
# ---------------------------
def _looks_like_pdf(url: str) -> bool:
    """URL 경로가 .pdf로 끝나는지 확인"""
    return urlparse(url).path.lower().endswith(".pdf")


def _pdf_bytes_to_text(b: bytes) -> str:
    """PDF 바이트 데이터를 텍스트로 변환"""
    with fitz.open(stream=b, filetype="pdf") as doc:
        pages = [page.get_text("text") for page in doc]
    return _clean_text("\n\n".join(pages))


# ---------------------------
# [신규] Selenium으로 HTML 가져오기
# ---------------------------
def _get_html_with_selenium(url: str, timeout: int = 20) -> str:
    """Selenium을 사용해 JS를 렌더링한 최종 HTML 소스를 반환"""
    if not HAS_SELENIUM:
        print("[WARN] Selenium이 없어 JS 렌더링을 스킵합니다.")
        return ""

    print(f"[INFO] 2차 시도: Selenium(Headless Chrome)으로 {url} 접근...")
    opts = webdriver.ChromeOptions()
    opts.add_argument('--headless=new')
    opts.add_argument('--no-sandbox')
    opts.add_argument('--disable-dev-shm-usage')
    opts.add_argument('--disable-gpu')
    opts.add_argument('--log-level=3')
    opts.add_experimental_option('excludeSwitches', ['enable-logging'])
    opts.add_argument(f"user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")

    driver = None
    try:
        driver = webdriver.Chrome(options=opts)
        driver.set_page_load_timeout(timeout) # 페이지 로드 타임아웃
        driver.get(url)
        # body 태그가 로드될 때까지 기다림
        WebDriverWait(driver, timeout).until(
            EC.presence_of_element_located((By.TAG_NAME, "body"))
        )
        # JS 렌더링을 위해 2초 추가 대기
        time.sleep(2)
        print("[INFO] Selenium 렌더링 완료.")
        return driver.page_source
    except Exception as e:
        print(f"[ERROR] Selenium 실행 중 오류: {e}")
        return ""
    finally:
        if driver:
            driver.quit()


# ---------------------------
# [신규] HTML → 텍스트 (로직 분리)
# ---------------------------
def _parse_html_to_text(html: str, url: str) -> str:
    """HTML 문자열을 입력받아 본문을 파싱하는 로직"""
    if not html:
        return ""
        
    soup = BeautifulSoup(html, "html.parser")

    if "attack.mitre.org/groups" in url:
        return _parse_mitre_group_page(soup)

    if "blog.cloudflare.com" in url:
        main = (
            soup.select_one("article") or
            soup.select_one(".post-content") or
            soup.select_one("[itemprop='articleBody']") or
            soup.select_one("#content") or
            soup
        )
        _drop_cloudflare_noise(main)
    else:
        _strip_noise(soup)
        main = _guess_main(soup)

    for tag in main(["script", "style", "nav", "footer", "aside", "form", "button", "noscript", "iframe"]):
        tag.decompose()

    parts: List[str] = []
    h1 = soup.find("h1")
    if h1:
        title = h1.get_text(strip=True)
        if title:
            parts.append(f"# {title}\n")

    body = main.get_text(separator="\n", strip=True)

    # 텍스트 레벨 클린업
    body = re.sub(r"\b\d+\s*분\s*읽기\b", "", body)
    body = re.sub(r"이\s*게시물은.*로도\s*이용할\s*수\s*있습니다\.?", "", body)

    parts.append(body)
    out = _clean_text("\n".join(parts))
    out = _dedupe_neighbor_lines(out)
    return out if out.strip() else ""


# ---------------------------
# [수정] 핵심: URL → 텍스트 (하이브리드)
# ---------------------------
def get_text_from_url(url: str, timeout: int = 20) -> str:
    """
    requests로 1차 시도 후, 결과가 부실하면 Selenium으로 2차 시도.
    PDF는 자동 감지하여 처리.
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Accept-Encoding": "gzip, deflate",
        "Accept": "text/html,application/xhtml+xml,application/xml,application/pdf;q=0.9,*/*;q=0.8",
        "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
    }
    html = ""
    
    # --- 1단계: Requests로 먼저 시도 ---
    try:
        print(f"[INFO] 1차 시도: Requests로 {url} 접근...")
        r = requests.get(url, headers=headers, timeout=timeout)
        r.raise_for_status()
        content_type = (r.headers.get("Content-Type") or "").lower()
        
        # PDF 감지
        if "application/pdf" in content_type or _looks_like_pdf(url):
            try:
                return _pdf_bytes_to_text(r.content) or "PDF 본문을 추출하지 못했습니다."
            except Exception as e:
                return f"PDF 처리 오류: {e}"

        # HTML 처리
        enc = r.apparent_encoding or r.encoding or "utf-8"
        html = r.content.decode(enc, errors="replace")

    except requests.Timeout:
        return f"타임아웃 오류: {url} 에 접근할 수 없습니다. (제한시간: {timeout}초)"
    except requests.RequestException as e:
        print(f"[WARN] Requests 요청 실패: {e}")
        # 403 (Forbidden) 같은 명백한 차단 시 Selenium으로 바로 재시도
        if e.response is not None and e.response.status_code in [403, 406]:
            html = _get_html_with_selenium(url, timeout) # 2단계(a): Selenium 재시도
        else:
            return f"요청 오류: {e}" # 그 외 네트워크 오류는 그냥 실패
    except Exception as e:
        return f"처리 중 알 수 없는 오류 발생 (Requests 단계): {e}"

    
    # --- 2단계: 파싱 및 Selenium 재시도 결정 ---
    try:
        parsed_text = _parse_html_to_text(html, url)
        
        # 파싱 결과가 너무 짧거나(150자 미만), JS 필요 문구가 있으면 Selenium 재시도
        is_too_short = len(parsed_text) < 5000
        is_js_warning = "javascript" in parsed_text.lower() and "enable" in parsed_text.lower()

        if (is_too_short or is_js_warning) and HAS_SELENIUM:
            print(f"[INFO] 1차 파싱 결과가 의심스러움 (길이: {len(parsed_text)}). Selenium으로 재시도합니다.")
            html_selenium = _get_html_with_selenium(url, timeout) # 2단계(b): Selenium 재시도
            
            if html_selenium:
                # Selenium 결과로 다시 파싱
                parsed_text_selenium = _parse_html_to_text(html_selenium, url)
                # Selenium 결과가 더 좋으면(길면) 그것으로 교체
                if len(parsed_text_selenium) > len(parsed_text):
                    print("[INFO] Selenium 파싱 결과가 더 우수하여 교체합니다.")
                    parsed_text = parsed_text_selenium
        
        if not parsed_text:
            return "본문 내용을 찾을 수 없습니다."
            
        return parsed_text
        
    except Exception as e:
        return f"HTML 파싱 중 오류 발생: {e}"


# ---------------------------
# (선택) ZDI 인덱스 크롤링
# ---------------------------
def crawl_zdi_blog_index(index_url: str, max_articles: Optional[int] = None) -> List[str]:
    """ZDI 블로그 목록 페이지에서 글 링크 수집 (Selenium)"""
    if not HAS_SELENIUM:
        print("[WARN] selenium 미설치 → crawl_zdi_blog_index() 건너뜀")
        return []
    urls: List[str] = []
    opts = webdriver.ChromeOptions()
    opts.add_argument('--headless=new')
    opts.add_argument('--no-sandbox')
    opts.add_argument('--disable-dev-shm-usage')
    opts.add_argument('--disable-gpu')
    opts.add_argument('--log-level=3')
    opts.add_experimental_option('excludeSwitches', ['enable-logging'])
    opts.add_argument(f"user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")

    driver = None
    try:
        driver = webdriver.Chrome(options=opts)
        driver.set_page_load_timeout(15)
        driver.get(index_url)
        WebDriverWait(driver, 15).until(
            EC.presence_of_element_located((By.CLASS_NAME, "blog-collection-item-link"))
        )
        soup = BeautifulSoup(driver.page_source, "html.parser")
        seen = set()
        for a in soup.find_all("a", class_="blog-collection-item-link"):
            href = a.get("href")
            if not href:
                continue
            u = urljoin(index_url, href)
            if u in seen:
                continue
            seen.add(u)
            urls.append(u)
            if max_articles and len(urls) >= max_articles:
                break
        return urls
    except Exception as e:
        print(f"[ZDI] 크롤링 오류: {e}")
        return []
    finally:
        if driver:
            driver.quit()
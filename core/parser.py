# -*- coding: utf-8 -*-
"""
core/parser.py — CTI/보안 블로그 본문 추출기 (Cloudflare/ATT&CK 최적화 + PDF 자동)
- get_text_from_url 단일 정의 (중복 정의 제거)
- PDF 자동 판별(Content-Type/확장자) → PyMuPDF 추출
- Cloudflare(ko-kr) 전용 노이즈: 언어 안내/읽기 시간/메타/공유·TOC 싹 제거
- MITRE ATT&CK 그룹 페이지 전용 파서 유지
- br(brotli) 강제 전송 시 수동 복호화 또는 재요청
- 본문 컨테이너 자동 추정 + 안전한 fallback
"""

from __future__ import annotations
import re
import requests
from typing import Optional, List, Dict
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

import fitz  # PyMuPDF

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    HAS_SELENIUM = True
except Exception:
    HAS_SELENIUM = False


# ---------------------------
# 공통 정리 유틸
# ---------------------------
def _clean_text(text: str) -> str:
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
    for sel in NOISE_SELECTORS:
        for tag in soup.select(sel):
            tag.decompose()
    for tag in soup(["script", "style", "noscript", "iframe"]):
        tag.decompose()


def _guess_main(soup: BeautifulSoup) -> BeautifulSoup:
    for sel in CANDIDATES:
        found = soup.select_one(sel)
        if found:
            return found
    return soup.body or soup


# ---------------------------
# Cloudflare 전용 정리
# ---------------------------
def _drop_cloudflare_noise(root: BeautifulSoup) -> None:
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
    # 문단/작은 메타 스팬에 박혀있을 수 있어서 넓게 훑음
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
    return urlparse(url).path.lower().endswith(".pdf")


def _pdf_bytes_to_text(b: bytes) -> str:
    with fitz.open(stream=b, filetype="pdf") as doc:
        pages = []
        for i in range(len(doc)):
            page = doc.load_page(i)
            pages.append(page.get_text("text"))
    return _clean_text("\n\n".join(pages))


# ---------------------------
# 핵심: URL → 텍스트
# ---------------------------
def get_text_from_url(url: str, timeout: int = 20) -> str:
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36"
        ),
        "Accept-Encoding": "gzip, deflate",
        "Accept": "text/html,application/xhtml+xml,application/xml,application/pdf;q=0.9,*/*;q=0.8",
        "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
    }
    try:
        r = requests.get(url, headers=headers, timeout=timeout)
        r.raise_for_status()
        content_type = (r.headers.get("Content-Type") or "").lower()
        enc_header = (r.headers.get("Content-Encoding") or "").lower()
        raw = r.content

        # brotli 강제 전송 시
        if enc_header == "br":
            try:
                import brotli
                raw = brotli.decompress(raw)
            except Exception:
                h2 = dict(headers)
                h2["Accept-Encoding"] = "gzip, deflate, identity"
                r2 = requests.get(url, headers=h2, timeout=timeout)
                r2.raise_for_status()
                raw = r2.content
                content_type = (r2.headers.get("Content-Type") or "").lower()

        # PDF?
        if "application/pdf" in content_type or _looks_like_pdf(url):
            try:
                return _pdf_bytes_to_text(raw) or "PDF 본문을 추출하지 못했습니다."
            except Exception as e:
                return f"PDF 처리 오류: {e}"

        # HTML
        enc = r.apparent_encoding or r.encoding or "utf-8"
        html = raw.decode(enc, errors="replace")
        soup = BeautifulSoup(html, "html.parser")

        # MITRE 특수
        if "attack.mitre.org/groups" in url:
            return _parse_mitre_group_page(soup)

        # Cloudflare
        if "blog.cloudflare.com" in url:
            main = (
                soup.select_one("article")
                or soup.select_one(".post-content")
                or soup.select_one("[itemprop='articleBody']")
                or soup.select_one("#content")
                or soup
            )
            _drop_cloudflare_noise(main)
        else:
            _strip_noise(soup)
            main = _guess_main(soup)

        # 잔여 잡태그
        for tag in main(["script", "style", "nav", "footer", "aside", "form", "button", "noscript", "iframe"]):
            tag.decompose()

        parts: List[str] = []
        h1 = soup.find("h1")
        if h1:
            title = h1.get_text(strip=True)
            if title:
                parts.append(f"# {title}\n")

        body = main.get_text(separator="\n", strip=True)

        # Cloudflare 잔재 방지: 한 번 더 텍스트 레벨 클린업
        body = re.sub(r"\b\d+\s*분\s*읽기\b", "", body)
        body = re.sub(r"이\s*게시물은.*로도\s*이용할\s*수\s*있습니다\.?", "", body)

        parts.append(body)
        out = _clean_text("\n".join(parts))
        out = _dedupe_neighbor_lines(out)
        return out if out.strip() else "본문 내용을 찾을 수 없습니다."

    except requests.Timeout:
        return f"타임아웃 오류: {url} 에 접근할 수 없습니다. (제한시간: {timeout}초)"
    except requests.RequestException as e:
        return f"요청 오류: {e}"
    except Exception as e:
        return f"처리 중 알 수 없는 오류 발생: {e}"


# ---------------------------
# (선택) ZDI 인덱스 크롤링
# ---------------------------
def crawl_zdi_blog_index(index_url: str, max_articles: Optional[int] = None) -> List[str]:
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

    driver = None
    try:
        driver = webdriver.Chrome(options=opts)
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
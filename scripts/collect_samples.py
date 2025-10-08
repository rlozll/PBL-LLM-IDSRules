import os, json, datetime, re, hashlib
from urllib.parse import urlparse
from core.parser import get_text_from_url

def short_hash(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8")).hexdigest()[:8]

def short_hash(s: str) -> str:
    """URL 문자열에서 고유 짧은 해시를 생성해서 파일명 충돌 방지"""
    return hashlib.sha1(s.encode('utf-8')).hexdigest()[:8]

ROOT = "/Users/kimnahyun/Desktop/pbl/PBL-LLM-IDSRules"
URLS_FILE = os.path.join(ROOT, "data", "sample_urls.txt")
OUT_DIR = os.path.join(ROOT, "data", "parsed_texts")

def sanitize(name: str) -> str:
    name = name.lower()
    name = re.sub(r'[^a-z0-9._-]+', '-', name).strip('-')
    return name[:120]  # 너무 길면 잘라냄

def guess_id(url: str) -> str:
    # URL 안에 CVE가 있으면 그걸 아이디로
    m = re.search(r'(cve-\d{4}-\d+)', url, re.I)
    if m: 
        return m.group(1).upper()
    # 없으면 도메인/슬러그 기반
    p = urlparse(url)
    tail = sanitize(p.path.split('/')[-1] or p.netloc)
    return (p.netloc + "-" + (tail or "index")).lower()

def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(URLS_FILE, "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    print(f"[i] {len(urls)}개 URL 처리 시작")
    ok, fail = 0, 0
    for url in urls:
        try:
            print(f"\n=== FETCH: {url}")
            text = get_text_from_url(url)
            if not text or "본문 내용을 찾을 수 없습니다." in text:
                raise ValueError("본문 추출 실패")

            source_id = guess_id(url)
            doc = {
                "source_id": source_id,
                "url": url,
                "text": text,
                "metadata": {
                    "collected_at": datetime.datetime.now(datetime.UTC).isoformat(),
                    "source_domain": urlparse(url).netloc,
                    "content_length": len(text),
                    "language": "auto",   # 일단 auto. 나중에 langdetect 붙이면 됨
                    "title": text.splitlines()[0][:160] if text else ""
                }
            }
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.replace(":", "_")
            uniq = short_hash(url)
            out_filename = f"{source_id}-{domain}-{uniq}.json"
            out_path = os.path.join(OUT_DIR, out_filename)
            with open(out_path, "w", encoding="utf-8") as out:
                json.dump(doc, out, ensure_ascii=False, indent=2)
            print(f"✅ saved: {out_path}")
            ok += 1
        except Exception as e:
            print(f"❌ fail: {url} -> {e}")
            fail += 1

    print(f"\n=== DONE: success={ok}, fail={fail}, out_dir={OUT_DIR}")

if __name__ == "__main__":
    main()

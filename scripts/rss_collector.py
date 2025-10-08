# scripts/rss_collector.py
import os, time, datetime, hashlib
import feedparser
from core.parser import get_text_from_url
from urllib.parse import urlparse
import json

RSS_FEEDS = [
    "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml",
    "https://www.zerodayinitiative.com/rss/alladvisories/",
    "https://blog.cloudflare.com/rss/",
    # 필요하면 MITRE, 보안 블로그 등 추가 가능
]

OUT_DIR = "data/rss_parsed"
os.makedirs(OUT_DIR, exist_ok=True)

def sanitize(s):
    return "".join(c if c.isalnum() else "-" for c in s)

def process_feed(feed_url):
    feed = feedparser.parse(feed_url)
    print(f"[{feed_url}] → {len(feed.entries)} entries")

    for entry in feed.entries:
        url = entry.link
        source_domain = urlparse(url).netloc
        uid = hashlib.md5(url.encode()).hexdigest()[:8]
        out_path = os.path.join(OUT_DIR, f"{sanitize(source_domain)}-{uid}.json")

        if os.path.exists(out_path):
            continue  # 이미 수집한 글은 패스

        try:
            text = get_text_from_url(url)
            if len(text) < 100:
                print(f"⚠️  {url} 텍스트 너무 짧음, 스킵")
                continue

            data = {
                "url": url,
                "source_domain": source_domain,
                "title": entry.get("title", ""),
                "collected_at": datetime.datetime.now(datetime.UTC).isoformat(),
                "text": text
            }
            with open(out_path, "w") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            print(f"✅ Saved {out_path}")
        except Exception as e:
            print(f"❌ {url} 수집 실패: {e}")

if __name__ == "__main__":
    import os, time, argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true", help="수집 1회만 실행하고 종료")
    args = parser.parse_args()

    def run():
        # 기존 수집 진입점 함수 호출 (너희 코드에서 쓰는 함수명으로 교체)
        collect_all_sources()  # 예시 함수명

    # 환경변수로 무한루프 끌 수도 있음: RSS_LOOP=0
    loop = os.getenv("RSS_LOOP", "1") != "0" and not args.once

    if loop:
        while True:
            run()
            print("=== RSS 수집 완료. 1시간 후 재실행 ===")
            time.sleep(3600)
    else:
        run()
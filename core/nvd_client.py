# core/nvd_client.py
import os
import re
import time
import logging
import requests
from typing import List, Dict, Optional, Any
from urllib.parse import quote_plus


def _nvd_headers() -> Dict[str, str]:
    h = {"Accept": "application/json", "User-Agent": "PBL-LLM-IDSRules/1.0 (+https://example.invalid)"}
    if NVD_API_KEY:
        h["apiKey"] = NVD_API_KEY
        log.info(f"[nvd] apiKey present: ***{NVD_API_KEY[-6:]}")
    else:
        log.warning("[nvd] apiKey missing")
    return h

# ──────────────────────────────────────────────────────────────────────────────
# 상수/환경
# ──────────────────────────────────────────────────────────────────────────────
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = (os.getenv("NVD_API_KEY") or "").strip().strip('"').strip("'")

CVE_RE = re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.I)

# 기본 rate limit 완화
DEFAULT_SLEEP = 0.6

log = logging.getLogger("core.nvd_client")


# ──────────────────────────────────────────────────────────────────────────────
# 유틸
# ──────────────────────────────────────────────────────────────────────────────
def _nvd_headers() -> Dict[str, str]:
    h = {
        "Accept": "application/json",
        "User-Agent": "PBL-LLM-IDSRules/1.0 (+https://example.invalid)"
    }
    if NVD_API_KEY:
        h["apiKey"] = NVD_API_KEY  # NVD v2 API header key name
    return h


def extract_cve_ids_from_text(text: str) -> List[str]:
    found = {m.upper() for m in CVE_RE.findall(text)}
    return sorted(found)


def simple_extract_product_version_candidates(text: str, max_candidates: int = 5) -> List[str]:
    """
    매우 간단한 heuristic: "Product X Y.Z" 또는 "X Y.Z" 같은 패턴을 잡아서 keywordSearch 값 후보로 반환
    (프로덕션이면 엔티티 인식 / CPE 정규화 필요)
    """
    candidates: List[str] = []
    # 예: "Apache 2.4.49", "OpenSSL 1.1.1k"
    for m in re.findall(r"([A-Za-z0-9\-\._]{3,40})\s+v?(\d+\.\d+(?:\.\d+)?(?:[a-z0-9\-]*)?)", text):
        prod = f"{m[0]} {m[1]}".strip()
        if "http" in prod.lower() or len(prod) < 4:
            continue
        candidates.append(prod)
        if len(candidates) >= max_candidates:
            break
    # fallback: 초간단 토큰 후보
    if not candidates:
        words = re.findall(r"[A-Za-z0-9\-\._]{3,40}", text)[:200]
        for w in words:
            if w[0].isalpha() and len(w) > 3:
                candidates.append(w)
            if len(candidates) >= max_candidates:
                break
    return candidates


# ──────────────────────────────────────────────────────────────────────────────
# NVD 쿼리
# ──────────────────────────────────────────────────────────────────────────────
def query_nvd_by_cve_raw(cve_id: str, timeout: int = 20) -> (Optional[Dict[str, Any]], int, str):
    """
    NVD 단건(CVE-ID) 조회(원형). (payload, http_status, header_message) 반환
    """
    headers = _nvd_headers()
    params = {"cveId": cve_id}
    try:
        r = requests.get(NVD_API_URL, params=params, headers=headers, timeout=timeout)
        hdr_msg = r.headers.get("message") or r.headers.get("Message") or ""
        log.info(f"NVD cveId={cve_id} HTTP={r.status_code}")
        if r.status_code != 200:
            return None, r.status_code, hdr_msg
        if not r.text:
            return None, 200, "empty body"
        return r.json(), 200, hdr_msg
    except Exception as e:
        log.error(f"query_nvd_by_cve_raw exception {e}")
        return None, -1, str(e)


def query_nvd_by_cve(cve_id: str, timeout: int = 20) -> Optional[Dict[str, Any]]:
    """
    (기존 호환) 성공 시 JSON, 실패 시 None
    """
    data, status, _ = query_nvd_by_cve_raw(cve_id, timeout=timeout)
    time.sleep(DEFAULT_SLEEP)
    if status == 200:
        return data
    log.warning(
        f"NVD single CVE query failed {cve_id} status={status}"
    )
    return None


def query_nvd_by_keyword(keyword: str, results_per_page: int = 50, timeout: int = 30) -> Optional[Dict[str, Any]]:
    headers = _nvd_headers()
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": results_per_page
    }
    try:
        r = requests.get(NVD_API_URL, params=params, headers=headers, timeout=timeout)
        log.info(f"NVD keywordSearch='{keyword}' HTTP={r.status_code} url={r.url}")
        if r.status_code != 200:
            log.warning(f"NVD keyword search failed status={r.status_code} message={r.headers.get('message')}")
            return None
        # sometimes content empty even 200
        if not r.text:
            log.warning("NVD returned empty body")
            return None
        time.sleep(DEFAULT_SLEEP)
        return r.json()
    except Exception as e:
        log.error(f"query_nvd_by_keyword exception {e}")
        return None


# ──────────────────────────────────────────────────────────────────────────────
# 폴백(키워드 기반)
# ──────────────────────────────────────────────────────────────────────────────
def mitre_fallback(keyword: str, limit: int = 20) -> List[Dict[str, Any]]:
    """
    MITRE CVE AWG simple fallback. 엔드포인트 정책/헤더 바뀔 수 있음.
    """
    try:
        url = f"https://cveawg.mitre.org/api/cve?keyword={quote_plus(keyword)}&limit={limit}"
        r = requests.get(url, timeout=15, headers={"User-Agent": "PBL-LLM-IDSRules/1.0"})
        log.info(f"MITRE fallback HTTP={r.status_code}")
        if r.status_code == 200:
            data = r.json()
            vulns = data.get("vulnerabilities") or data.get("data") or []
            return vulns
    except Exception as e:
        log.warning(f"mitre_fallback failed: {e}")
    return []


def circl_fallback(keyword: str, limit: int = 50) -> List[Dict[str, Any]]:
    """
    CIRCL / vulnerability-lookup fallback attempt. Public API가 HTML을 줄 때가 있어 엄격 체크.
    """
    try_endpoints = [
        f"https://vulnerability.circl.lu/rest/search/{quote_plus(keyword)}",
        f"https://vulnerability.circl.lu/rest/search/{quote_plus(keyword)}?limit={limit}",
        f"https://cve.circl.lu/api/search?query={quote_plus(keyword)}",
    ]
    for url in try_endpoints:
        try:
            r = requests.get(
                url, timeout=12,
                headers={"Accept": "application/json", "User-Agent": "PBL-LLM-IDSRules/1.0"}
            )
            log.info(f"circl_try {url} status={r.status_code} ct={r.headers.get('Content-Type')}")
            if r.status_code != 200:
                continue
            ct = r.headers.get("Content-Type", "")
            if "application/json" not in ct:
                log.warning("circl response not JSON, skip")
                continue
            data = r.json()
            # normalize
            if isinstance(data, dict) and data.get("results"):
                items = data["results"]
            elif isinstance(data, list):
                items = data
            elif isinstance(data, dict) and data.get("vulnerabilities"):
                items = data["vulnerabilities"]
            else:
                items = []
            return items[:limit]
        except Exception as e:
            log.warning(f"circl try error {e}")
    return []


# ──────────────────────────────────────────────────────────────────────────────
# 폴백(CVE 단건 기반)
# ──────────────────────────────────────────────────────────────────────────────
def _circl_lookup_by_cve(cve_id: str) -> Optional[Dict[str, Any]]:
    """
    CIRCL에서 CVE 단건 조회 시도 (여러 엔드포인트 시도)
    """
    endpoints = [
        f"https://vulnerability.circl.lu/rest/cve/{quote_plus(cve_id)}",
        f"https://cve.circl.lu/api/cve/{quote_plus(cve_id)}",
    ]
    for url in endpoints:
        try:
            r = requests.get(url, headers={"Accept": "application/json", "User-Agent": "PBL-LLM-IDSRules/1.0"}, timeout=12)
            log.info(f"circl_by_cve {url} status={r.status_code} ct={r.headers.get('Content-Type')}")
            if r.status_code != 200:
                continue
            ct = r.headers.get("Content-Type", "")
            if "application/json" not in ct:
                continue
            return r.json()
        except Exception as e:
            log.warning(f"circl_by_cve error {e}")
    return None


def _mitre_lookup_by_cve(cve_id: str) -> Optional[Dict[str, Any]]:
    """
    MITRE에서 CVE 키워드로 단건 근사 조회 (정확 단건 API는 조직 헤더 등 요구 가능)
    """
    try:
        url = f"https://cveawg.mitre.org/api/cve?keyword={quote_plus(cve_id)}&limit=1"
        headers = {
            "Accept": "application/json",
            "User-Agent": "PBL-LLM-IDSRules/1.0",
            "CVE-API-ORG": "pbl-ids"
        }
        r = requests.get(url, headers=headers, timeout=12)
        log.info(f"mitre_by_cve status={r.status_code}")
        if r.status_code == 200:
            try:
                j = r.json()
            except Exception:
                return {"raw_text": r.text}
            # 다양한 shape 대응
            if isinstance(j, dict) and j.get("vulnerabilities"):
                return j["vulnerabilities"][0]
            return j
    except Exception as e:
        log.warning(f"mitre_by_cve error {e}")
    return None


def fetch_cve_with_fallback(cve_id: str) -> Dict[str, Any]:
    """
    NVD -> CIRCL -> MITRE 순으로 CVE 단건 조회. 어떤 소스를 사용했는지 기록.
    반환: {"nvd":..., "circl":..., "mitre":..., "used": "nvd|circl|mitre|none", "status": int, "message": str}
    """
    result: Dict[str, Any] = {
        "nvd": None, "circl": None, "mitre": None,
        "used": "none", "status": -1, "message": ""
    }

    # 1) NVD
    payload, status, hdr_msg = query_nvd_by_cve_raw(cve_id)
    result["status"] = status
    if hdr_msg:
        result["message"] = f"NVD: {hdr_msg}"
    if status == 200 and payload:
        vulns = payload.get("vulnerabilities") or []
        if vulns:
            result["nvd"] = vulns[0].get("cve") or vulns[0]
            result["used"] = "nvd"
            return result
        # 빈 응답이면 폴백 계속

    # 2) CIRCL
    circl = _circl_lookup_by_cve(cve_id)
    if circl:
        result["circl"] = circl
        result["used"] = "circl"
        return result

    # 3) MITRE
    mitre = _mitre_lookup_by_cve(cve_id)
    if mitre:
        result["mitre"] = mitre
        result["used"] = "mitre"
        return result

    return result


# ──────────────────────────────────────────────────────────────────────────────
# 통합 검색 (텍스트 → CVE/NVD + 폴백)
# ──────────────────────────────────────────────────────────────────────────────
def search_from_text(text: str, max_cves: int = 10) -> Dict[str, Any]:
    """
    텍스트에서 CVE를 뽑고, CVE 단건 우선 조회(실패 시 CVE 단위 폴백 기록).
    CVE가 전혀 없거나 전부 실패면 product-version 후보로 NVD keywordSearch를 시도하고,
    그마저도 실패한 키워드는 키워드 단위 폴백(CIRCL/MITRE) 결과를 기록한다.
    응답 스키마는 기존과 호환되도록 유지:
      - nvd: { "CVE-XXXX-YYYY": <NVD cve json or None> }
      - fallbacks: {
          "per_cve": { "CVE-...": {used,status,message,has_circl,has_mitre} },
          "keyword": { "<cand>": { "nvd_ok": bool, "circl": [...], "mitre": [...] } }
        }
    """
    response: Dict[str, Any] = {
        "extracted_cve_ids": [],
        "nvd": {},
        "fallbacks": {"per_cve": {}, "keyword": {}}
    }

    # 1) CVE 추출
    cve_ids = extract_cve_ids_from_text(text)
    response["extracted_cve_ids"] = cve_ids

    # 2) CVE 단건 조회 + 폴백
    nvd_results: Dict[str, Any] = {}
    for cid in cve_ids[:max_cves]:
        info = fetch_cve_with_fallback(cid)

        # 기존 스키마 유지: nvd dict에는 NVD가 성공한 경우만 채움, 아니면 None
        nvd_results[cid] = info["nvd"] if info.get("nvd") else None

        # 폴백 상세는 per_cve로 기록
        response["fallbacks"]["per_cve"][cid] = {
            "used": info.get("used"),
            "status": info.get("status"),
            "message": info.get("message", ""),
            "has_circl": bool(info.get("circl")),
            "has_mitre": bool(info.get("mitre"))
        }

        # rate limit
        time.sleep(DEFAULT_SLEEP)

    response["nvd"] = nvd_results

    # 3) 키워드 검색 (CVE가 없거나 전부 실패한 경우)
    if not cve_ids or all(v is None for v in nvd_results.values()):
        candidates = simple_extract_product_version_candidates(text, max_candidates=6)
        response["keyword_candidates"] = candidates

        keyword_results: Dict[str, Optional[Dict[str, Any]]] = {}
        for cand in candidates:
            res = query_nvd_by_keyword(cand, results_per_page=50)
            keyword_results[cand] = res

            # 키워드별 폴백 기록 (NVD 실패 시만 실행)
            fb_entry = {"nvd_ok": bool(res), "circl": [], "mitre": []}
            if not res:
                # CIRCL / MITRE 키워드 폴백
                fb_entry["circl"] = circl_fallback(cand, limit=50)
                fb_entry["mitre"] = mitre_fallback(cand, limit=20)
            response["fallbacks"]["keyword"][cand] = fb_entry

            time.sleep(DEFAULT_SLEEP)

        response["nvd_keyword"] = keyword_results

    return response
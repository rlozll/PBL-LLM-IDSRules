# -*- coding: utf-8 -*-
"""
core/chunking.py — 한국어 친화 청킹 도구
- 문장 기반 청킹: max_chars + 문장 겹침(overlap_sents)
- 토큰 근사 청킹: 한국어 문자/토큰 비율 보정(2.2~2.6 chars/token 동적), 문장 경계 우선
"""

from __future__ import annotations
import re
from typing import List


# ---------------------------
# 문장 분할 (한국어/영어 혼합 안전)
# ---------------------------
_SENT_SEP = re.compile(
    r"""
    (?:
        (?<=[\.!?])         # 영어 문장부호 뒤
        (?:\s+|$)
    )
    |
    (?:
        (?<=[다요음임죠죠욥욧습닙합합니]\.)  # 한국어 종결 어절 + '.' 패턴들(느슨)
        (?:\s+|$)
    )
    |
    (?:
        (?<=[\u3002])       # '。'
        (?:\s+|$)
    )
    """,
    re.VERBOSE
)

def _split_sentences(text: str) -> List[str]:
    # 줄바꿈을 공백으로 일단 말아 중간 개행 잡음 제거 → 이후 _SENT_SEP로 다시 분할
    fused = re.sub(r"[ \t]*\n[ \t]*", " ", text)
    parts = [s.strip() for s in _SENT_SEP.split(fused) if s and s.strip()]
    return parts


# ---------------------------
# 문장 기반 청킹
# ---------------------------
def chunk_by_sentences(text: str, max_chars: int = 3000, overlap_sents: int = 1) -> List[str]:
    sents = _split_sentences(text)
    chunks: List[str] = []
    buf: List[str] = []
    cur = 0
    for s in sents:
        if cur + len(s) + (1 if cur else 0) > max_chars and buf:
            chunks.append(" ".join(buf).strip())
            if overlap_sents > 0:
                buf = buf[-overlap_sents:]
                cur = sum(len(x) for x in buf) + max(0, len(buf) - 1)
            else:
                buf, cur = [], 0
        if cur > 0:
            buf.append(s)
            cur += 1 + len(s)  # 공백 포함
        else:
            buf = [s]
            cur = len(s)
    if buf:
        chunks.append(" ".join(buf).strip())
    return chunks


# ---------------------------
# 한국어 토큰 길이 근사
# ---------------------------
def _approx_token_len_ko(text: str) -> int:
    n = len(text)
    if n == 0:
        return 0
    hangul = sum(1 for c in text if '\uac00' <= c <= '\ud7a3')
    ratio = hangul / n  # 0~1
    # 한글 비율이 높을수록 문자/토큰 비율이 작아짐(=토큰이 더 많이 필요)
    # 2.6(영문/혼합) ~ 2.2(순한글)에 가깝게 보정
    chars_per_token = 2.6 - 0.4 * ratio  # 2.2~2.6
    return max(1, int(n / chars_per_token))


# ---------------------------
# 근사 토큰 기반 청킹 (문장 경계 우선)
# ---------------------------
def chunk_by_tokens_approx(text: str, max_tokens: int = 1500, overlap_ratio: float = 0.05) -> List[str]:
    sents = _split_sentences(text)
    chunks: List[str] = []
    buf: List[str] = []
    cur_tok = 0

    def _tok_join(parts: List[str]) -> int:
        return _approx_token_len_ko(" ".join(parts))

    for s in sents:
        s_tok = _approx_token_len_ko(s)
        if cur_tok + s_tok > max_tokens and buf:
            chunks.append(" ".join(buf).strip())
            if overlap_ratio > 0:
                keep = max(1, int(len(buf) * overlap_ratio))
                buf = buf[-keep:]
                cur_tok = _tok_join(buf)
            else:
                buf, cur_tok = [], 0
        buf.append(s)
        cur_tok += s_tok

    if buf:
        chunks.append(" ".join(buf).strip())
    return chunks
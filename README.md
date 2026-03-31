<div align="center">

```
 ██████╗████████╗██╗███╗  ██╗████████╗       █████╗ ██╗
██╔════╝╚══██╔══╝██║████╗ ██║╚══██╔══╝      ██╔══██╗██║
██║        ██║   ██║██╔██╗██║   ██║    ████ ███████║██║
██║        ██║   ██║██║╚████║   ██║         ██╔══██║██║
╚██████╗   ██║   ██║██║ ╚███║   ██║         ██║  ██║██║
 ╚═════╝   ╚═╝   ╚═╝╚═╝  ╚══╝   ╚═╝         ╚═╝  ╚═╝╚═╝
```

### AI-based Real-time Unstructured CTI Analysis and IDS Rule Generator

**AI 기반 실시간 비정형 CTI 분석 및 IDS Rule 생성기**

<br/>

[![Python](https://img.shields.io/badge/Python-3.12+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18+-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev/)
[![Gemini](https://img.shields.io/badge/Google_Gemini-API-4285F4?style=flat-square&logo=google&logoColor=white)](https://ai.google.dev/)
[![Snort](https://img.shields.io/badge/Snort-2.9-CC0000?style=flat-square&logo=snort&logoColor=white)](https://www.snort.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

<br/>

> 사이버 위협 인텔리전스(CTI) 문서를 자동으로 수집·분석하고,  
> LLM을 통해 Snort IDS Rule을 실시간으로 생성·검증하는 통합 보안 대시보드

</div>

---

## 🚨 배경 및 필요성

현대 사이버 위협 환경에서 **CTI(Cyber Threat Intelligence)** 의 중요성은 날로 높아지고 있습니다. 그러나 기존의 CTI 대응 방식은 다음과 같은 심각한 한계를 가지고 있습니다.

| 문제점 | 내용 |
|--------|------|
| 🐢 **느린 대응 속도** | 분석가가 문서를 직접 검토하는 수작업 구조로 인해 대응 속도 저하 |
| 🎯 **0-day 공격에 취약** | 신규 위협 발생 시 Rule 생성까지 걸리는 시간 동안 무방비 노출 |
| 👤 **사람에 의존** | 분석가의 역량과 컨디션에 따라 분석 품질이 달라짐 |
| 📄 **비정형 데이터 처리 어려움** | 블로그, 리포트, 공시문 등 다양한 형태의 CTI 문서 처리 불가 |

**CTINT_AI**는 이 모든 문제를 해결합니다. CTI 문서 URL 하나만 입력하면, 자동으로 분석하여 즉시 사용 가능한 Snort IDS Rule을 생성해드립니다.

---

## ✨ 주요 기능

### 🔍 수동 분석 (Dashboard Home)
원하는 CTI 문서의 URL을 입력하면, 실시간으로 분석이 진행됩니다.
- IoC(침해 지표) 자동 추출: IP, 도메인, URL, 해시, CVE 등
- Snort 2.9 Rule 자동 생성
- 2단계 Rule 검증 (정적 분석 + Snort 문법 검증)
- 상세 설명 제공: 공격 원리, IDS 설정 권고, 사용자 조치 사항

### 📡 자동 CTI 수집 (CTI List)
주요 보안 기관과 벤더의 RSS 피드를 **24시간 자동 모니터링**합니다.
- Mandiant, Palo Alto Unit 42, CrowdStrike, Microsoft Security 등 10개+ 피드 지원
- CISA, CERT-KR 등 정부 기관 공식 피드 포함
- 원하는 출처만 필터링하여 열람 가능
- 클릭 한 번으로 수동 분석에 URL 자동 입력

### 🔖 북마크 자동 분석 (Bookmarked Page)
자주 참고하는 사이트를 북마크에 등록하면 **신규 글이 게시될 때마다 자동으로 분석**합니다.
- RSS 피드 등록으로 새 글 자동 감지 (30분 주기)
- 분석 완료된 Rule과 설명을 즉시 열람 가능

### 📜 분석 이력 관리 (History)
수동 분석을 진행한 모든 기록을 저장하고 관리합니다.
- 생성된 Rule과 검증 결과, 설명 재열람 가능
- 과거 분석 기반의 위협 동향 파악

---

## 🏗 시스템 아키텍처

```
┌─────────────────────────────────────────────────────────────────┐
│                     Frontend (React)                            │
│                                                                 │
│  Dashboard Home │ CTI List │ Bookmarked Page │ History          │
└──────────────────────────┬──────────────────────────────────────┘
                           │ REST API (JWT Auth)
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Backend (FastAPI)                             │
│                                                                 │
│  ┌──────────────┐    ┌─────────────┐   ┌──────────────────────┐ │
│  │ API Endpoints│    │  SQLite DB  │   │  scripts/            │ │
│  │ JWT/OAuth2   │◄──►│ - History   │   │  rss_collector.py    │ │
│  │ APScheduler  │    │ - CTI List  │   │  nvd_collector.py    │ │
│  └──────┬───────┘    │ - Bookmark  │   └──────────────────────┘ │
│         │            └─────────────┘                            │
│         ▼                                                       │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                  Core Engine (Python)                     │  │
│  │                                                           │  │
│  │  parser.py          llm_handler.py        validator.py    │  │
│  │  ┌─────────────┐   ┌────────────────┐   ┌─────────────┐   │  │
│  │  │ 하이브리드   │   │ 3-Step 프롬프트 │   │ 2단계 검증  │   │  │
│  │  │ CTI 파서    │──►│ 체이닝          │──►│ 시스템      │   │  │
│  │  │             │   │                │   │            │   │  │
│  │  │ requests    │   │ IoC 추출       │   │ 정적 분석   │   │  │
│  │  │ + Selenium  │   │ Rule 생성      │   │ Snort 검증  │   │  │
│  │  │ Fallback    │   │ 설명 생성       │  │ (WSL)       │   │  │
│  │  └─────────────┘   └───────┬────────┘   └─────────────┘  │  │
│  │                            │                             │  │
│  │                     Google Gemini API                     │ │
│  └───────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────┘
```

### 워크플로우

**수동 분석 흐름:**
```
사용자 URL 입력
   → FastAPI (JWT 인증)
   → parser.py (하이브리드 CTI 파싱)
   → llm_handler.py (3-Step 프롬프트 체이닝)
      ├─ Step 1: IoC 추출 (Gemini API)
      ├─ Step 2: Snort Rule 생성 (Gemini API)
      └─ Step 3: 상세 설명 생성 (Gemini API)
   → validator.py (2단계 하이브리드 검증)
      ├─ 정적 분석 (잠재적 오탐·성능 저하 요소 식별)
      └─ 문법 검증 (Snort 2.9 엔진 실행)
   → SQLite DB (History 저장)
   → 프론트엔드 결과 반환
```

**자동 수집 흐름:**
```
APScheduler (1시간 주기)
   → rss_collector.py
   → 10개+ RSS 피드 수집
   → SQLite DB (CTI List 저장)

APScheduler (30분 주기)
   → bookmark_processor.py
   → 등록된 사이트 신규 글 감지
   → Core Engine 자동 분석
   → SQLite DB (Bookmarked 결과 저장)
```

---

## ⚔️ 기존 기술과의 차이점

|  | 기존 보안 솔루션 (이벤트·로그 기반) | 기존 CTI 기반 분석 | **CTINT_AI** |
|--|--|--|--|
| **신속성** | 사고 발생 후 분석 및 대응 | 수동 분석으로 지연 발생 | ⚡ **골든 타임 확보** — 24시간 모니터링, 1분 내 보고서 분석, Rule 초안 자동 생성 |
| **신뢰성** | 오탐 발생 가능성 높음 | 분석자의 역량에 의존적 | 🔒 **2단계 하이브리드 검증** — 정적 분석 + Snort 엔진 문법 검증 자동화 |
| **사용성** | 전문성 요구 (Rule 직접 작성) | 전문적 CTI 분석가 필요 | 🧠 **3단계 프롬프트 체이닝** — IoC 추출 → Rule 생성 → 설명 생성 자동화 |
| **범용성** | 특정 포맷, 이벤트에 종속 | 정형화된 포맷만 처리 | 🌐 **하이브리드 CTI 파서** — requests + Selenium 단계적 결합으로 비정형 문서 지원 |

---

## 🛠 기술 스택

### Frontend
| 기술 | 설명 |
|------|------|
| React (JavaScript) | 웹 대시보드 UI |
| CSS | 스타일링 |

### Backend
| 기술 | 설명 |
|------|------|
| Python 3.12+ | 핵심 로직 |
| FastAPI | REST API 서버 |
| Uvicorn | ASGI 서버 |
| SQLite | 데이터베이스 |
| APScheduler | 백그라운드 작업 스케줄링 |
| Google Gemini API | LLM 기반 CTI 분석 및 Rule 생성 |
| Selenium | JS 렌더링 페이지 파싱 (Fallback) |
| BeautifulSoup4 | HTML 파싱 |
| WSL (Ubuntu) + Snort 2.9 | Rule 문법 검증 |

---

## 📁 프로젝트 구조 (주요 구조 중심)

```
PBL-LLM-IDSRules/
├── app.py                        # FastAPI 메인 서버 (API 엔드포인트, 스케줄러)
│
├── core/                         # 핵심 분석 엔진
│   ├── parser.py                 # 하이브리드 CTI 파서 (requests + Selenium Fallback)
│   ├── llm_handler.py            # 3-Step 프롬프트 체이닝 (IoC → Rule → 설명)
│   └── vt_client.py              # VirusTotal API 연동 클라이언트
│
├── utils/                        # 유틸리티 모듈
│   ├── db.py                     # SQLite DB 연동 (History, CTI List, Bookmark)
│   ├── validator.py              # 2단계 하이브리드 Rule 검증 (정적 + Snort)
│   └── deploy.py                 # Rule 배포 유틸리티
│
├── scripts/                      # 백그라운드 스크립트
│   ├── rss_collector.py          # RSS 피드 자동 수집 (CTI List)
│   ├── bookmark_processor.py     # 북마크 사이트 신규 글 자동 분석
│   ├── virustotal_collector.py   # VirusTotal 자동 수집
│   ├── api_collector.py          # 외부 API 기반 수집 (Placeholder)
│   ├── orchestrator.py           # 스케줄러 오케스트레이터
│   └── deploy.sh                 # Snort Rule 배포 쉘 스크립트
│
├── frontend/                     # React 프론트엔드
│   ├── src/
│   │   ├── pages/
│   │   │   ├── DashboardHome.jsx # 수동 분석 페이지
│   │   │   ├── CtiList.jsx       # CTI 목록 페이지
│   │   │   ├── BookmarkedPage.jsx# 북마크 자동 분석 페이지
│   │   │   └── History.jsx       # 분석 이력 페이지
│   │   └── ...
│   └── package.json
│
├── data/                         # 수집 데이터 저장소
│   └── virustotal/
│
├── logs/                         # 로그 파일
│   ├── rss_collector.log
│   └── bookmark_processor.log
│
├── .env                          # 환경 변수 (API 키 등) — .gitignore에 포함
├── .gitignore
└── requirements.txt
```

---

## 🚀 설치 및 실행

### 사전 요구사항

- Python 3.12+
- Node.js 18+
- WSL (Ubuntu) + Snort 2.9 *(Rule 검증 기능 사용 시 필요)*
- Chrome + ChromeDriver *(Selenium Fallback 사용 시 필요)*

### 1. 저장소 클론

```bash
git clone https://github.com/rlozll/PBL-LLM-IDSRules.git
cd PBL-LLM-IDSRules
```

### 2. 환경 변수 설정

`.env` 파일을 프로젝트 루트에 생성합니다:

```env
# Google Gemini API 키 (필수)
GOOGLE_API_KEY=your_google_gemini_api_key_here

# 대시보드 로그인 비밀번호 (필수)
DASHBOARD_PASSWORD=your_dashboard_password

# JWT 설정
JWT_SECRET_KEY=your_jwt_secret_key_here
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=480

# LLM 모델 설정 (선택, 기본값: gemini-pro)
LLM_MODEL=gemini-pro

# VirusTotal API 키 (선택)
VT_API_KEY=your_virustotal_api_key_here
```

### 3. 백엔드 설치 및 실행

```bash
# 가상환경 생성 및 활성화
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate

# 의존성 설치
pip install -r requirements.txt

# 백엔드 서버 실행
python app.py
```

백엔드 서버가 `http://127.0.0.1:8000` 에서 실행됩니다.  
API 문서: `http://127.0.0.1:8000/docs`

### 4. 프론트엔드 설치 및 실행

```bash
cd frontend

# 의존성 설치
npm install

# 개발 서버 실행
npm start
```

프론트엔드가 `http://localhost:3000` 에서 실행됩니다.

### 5. (선택) Snort 2.9 설치 — Rule 검증 기능

WSL(Ubuntu) 환경에서 Snort를 설치합니다:

```bash
sudo apt-get update
sudo apt-get install snort
snort --version
```

---

## 📖 사용 방법

### 로그인

1. `http://localhost:3000` 접속
2. `.env`에 설정한 `DASHBOARD_PASSWORD`로 로그인

### 수동 분석 (Dashboard Home)

1. 메인 화면의 URL 입력란에 분석할 CTI 문서 URL을 입력
2. **분석 시작** 버튼 클릭
3. 분석 완료 후 다음 결과를 확인:
   - **소스 목록**: 분석에 사용된 CTI 문서
   - **추출된 IoC**: IP, 도메인, URL, 해시, CVE 등
   - **생성된 Rule**: 즉시 사용 가능한 Snort 2.9 Rule
   - **검증 결과**: 정적 분석 및 문법 검증 통과 여부
   - **상세 설명**: 공격 원리, IDS 설정 권고, 사용자 조치 사항

```
# 입력 예시
https://unit42.paloaltonetworks.com/cve-2024-xxxxx/

# 출력 예시 (Snort Rule)
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS \
  (msg:"CTINT_AI - CVE-2024-XXXXX Exploit Attempt"; \
   pcre:"/\/path\/to\/exploit/i"; \
   sid:1000001; rev:1; reference:cve,2024-xxxxx;)
```

### CTI List

1. 사이드바에서 **CTI List** 클릭
2. 주요 보안 피드에서 자동 수집된 최신 CTI 문서 열람
3. 사이트별 필터링 기능으로 원하는 출처만 선택
4. 우측 아이콘 클릭 → 링크 복사 또는 수동 분석에 URL 자동 입력

### Bookmarked Page

1. 사이드바에서 **Bookmarked Page** 클릭
2. RSS 피드 URL을 등록하면 30분마다 신규 글 자동 분석
3. 분석 완료된 글 클릭 → 자동 생성된 Rule과 설명 즉시 확인

### History

1. 사이드바에서 **History** 클릭
2. 과거 수동 분석 결과 전체 열람
3. 항목 클릭 → 저장된 Rule, 검증 결과, 설명 재확인

---

## 🔬 핵심 로직 상세

### 1. 하이브리드 CTI 파서 (`core/parser.py`)

비정형 CTI 문서의 다양한 형태를 처리하기 위해 **2단계 Fallback 구조**를 채택했습니다.

```
1단계: requests로 HTTP 요청
   ├─ 성공 + 충분한 본문(5000자+) → 즉시 파싱
   └─ 실패(403/406) 또는 본문 부족 → 2단계 진행

2단계: Selenium Headless Chrome으로 JS 렌더링 후 재파싱
   → Cloudflare, SPA, JS 렌더링 필수 사이트 대응
```

PDF 자동 감지, MITRE ATT&CK 전용 파서, Cloudflare 블로그 최적화 등도 포함합니다.

### 2. 3-Step 프롬프트 체이닝 (`core/llm_handler.py`)

단일 프롬프트가 아닌 **3단계 순차 호출 구조**로 LLM 분석의 깊이와 신뢰도를 높입니다.

```
Step 1 — IoC 추출
  Input : CTI 본문 (최대 12,000자)
  Output: { cve: [], ip: [], domain: [], url: [], hash: [] }

Step 2 — Snort Rule 생성
  Input : 추출된 IoC
  Output: Snort 2.9 Rule 1줄
  조건  : PCRE 기반, Behavior 패턴 중심, 오탐 최소화

Step 3 — 설명 생성
  Input : IoC + Rule
  Output: {
    rule_analysis    : 공격 원리 및 탐지 메커니즘 설명,
    ids_recommendation: IDS 설정 변경 권고사항,
    user_action      : 일반 사용자/개발자 조치 사항
  }
```

### 3. 2단계 하이브리드 검증 (`utils/validator.py`)

LLM 환각(Hallucination) 및 문법 오류로 인한 잘못된 Rule 배포를 방지합니다.

```
Stage 1 — 정적 분석
  ├─ 잠재적 오탐 유발 패턴 검사 (너무 일반적인 content 등)
  ├─ 성능 저하 요소 식별 (정규식 복잡도 등)
  └─ PCRE 괄호 짝 검사

Stage 2 — Snort 문법 검증
  └─ WSL Ubuntu 환경에서 Snort 2.9 엔진 직접 실행
     → 문법 오류 시 Fail 처리, 통과 시 DB 저장
```
---

<div align="center">

2025 서울여자대학교 종단형 PBL 성과 발표

**CTINT_AI Team** — *Securing the Golden Hour, One Rule at a Time*

</div>



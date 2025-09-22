# PBL-LLM-IDSRules 

/cti-rule-generator/

|

├── app.py             # 📜 메인 Streamlit 애플리케이션 파일 (UI 및 전체 흐름 제어)

|

├── core/

│   ├── parser.py      # 📄 웹/PDF에서 텍스트를 추출하고 전처리하는 모듈

│   └── llm_handler.py # 🤖 LangChain을 사용하여 LLM 프롬프트를 만들고 API를 호출하는 모듈

|

├── utils/

│   └── validator.py   # ✅ 생성된 Rule의 문법적 유효성을 검증하는 유틸리티 모듈

|

├── scripts/

│   └── deploy.sh      # 🚀 IDS 서버에 Rule을 배포하는 쉘 스크립트 (app.py에서 호출)

|

├── requirements.txt   # 📦 필요한 파이썬 라이브러리 목록

|

└── README.md          # 📖 프로젝트 설명서
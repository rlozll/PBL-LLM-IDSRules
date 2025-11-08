// src/components/MainView.js
import React, { useState, useRef, useEffect } from 'react';
import { generateRule } from '../api';
import './MainView.css';
//import { FiUpload } from 'react-icons/fi';
import userIcon from './icons/user.svg';
import searchIcon from './icons/search.svg';
import addURLIcon from './icons/addURL.svg';
import profileIcon from './icons/profile.svg';
import pdfIcon from './icons/pdf.svg';
import linkIcon from './icons/Link1.svg';
import { FiLogOut } from 'react-icons/fi'; 
import profileMenuIcon from './icons/profileMenu.svg'; 

function MainView({ onLogout }) {
  const [url, setUrl] = useState('');
  const [file, setFile] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef(null);

  // 메뉴 바깥 클릭 시 닫기
  useEffect(() => {
    const handleClickOutside = (e) => {
      if (menuRef.current && !menuRef.current.contains(e.target)) {
        setMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleLogout = () => {
    //  로그아웃 처리 후 로그인 페이지로 이동
    localStorage.removeItem('token'); // 토큰 등 세션 초기화
    window.location.href = '/login';
    onLogout(); // 부모(App.js)의 handleLogout 호출
  };

  const fileInputRef = useRef(null);

  const handleFileButtonClick = () => { fileInputRef.current.click(); };
  const handleFileChange = (event) => {
    const selectedFile = event.target.files[0];
    if (selectedFile) {
      setFile(selectedFile);
      setUrl('');
      console.log('File selected:', selectedFile.name);
    }
  };

  const handleAnalyze = async () => {
    if (!url && !file) {
      setError('URL을 입력하거나 PDF 파일을 업로드하세요.');
      return;
    }
    setIsLoading(true);
    setResult(null);
    setError('');

    let response;
    if (url) {
      response = await generateRule(url);
    } else if (file) {
      setError('PDF 파일 분석 기능은 아직 구현되지 않았습니다.');
      setIsLoading(false);
      return;
    }

    if (response && response.ok) {
        setResult(response.data);
    } else {
        const errorDetail = response.data?.detail?.error || response.data?.detail || response.data?.error || `API Error (${response.status})`;
        setError(`분석 실패: ${errorDetail}`);
        console.error("Analysis failed:", response.status, response.data);
    }
    setIsLoading(false);
  };

  const handleCopyRule = () => {
    if (result && result.generated_rule) {
      navigator.clipboard.writeText(result.generated_rule);
      alert('Rule이 클립보드에 복사되었습니다.');
    }
  };

  const handleDeployRule = () => {
      if (result && result.validation_result.startsWith("Success")) {
          alert('배포 기능 호출 (구현 필요)');
      } else {
          alert('검증에 성공한 Rule만 배포할 수 있습니다.');
      }
  }

  // --- ▼▼▼▼▼ 설명 객체를 렌더링하는 헬퍼 함수 ▼▼▼▼▼ ---
  const renderExplanation = (explanation) => {
    // explanation이 문자열(오류 메시지 등)인 경우 그대로 표시
    if (typeof explanation === 'string') {
      return <p>{explanation}</p>;
    }
    // explanation이 객체인 경우 (성공 시)
    if (typeof explanation === 'object' && explanation !== null && !explanation.error) {
      return (
        <div>
          <h4>규칙 분석 (전문가용)</h4>
          <p>{explanation.rule_analysis}</p>
          <h4>IDS 설정 권장 사항</h4>
          <p>{explanation.ids_recommendation}</p>
          <h4>일반 사용자/개발자 조치 사항</h4>
          <p>{explanation.user_action}</p>
        </div>
      );
    }
    // explanation이 객체인데 오류가 포함된 경우
    if (explanation && explanation.error) {
      return <p style={{ color: 'red' }}>설명 생성 실패: {explanation.error}</p>;
    }
    // 그 외 알 수 없는 경우
    return <p>설명 데이터를 불러올 수 없습니다.</p>;
  };
  // --- ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲ ---



return (
  <>
    {/* ===== 상단 바 ===== */}
    <div className="topbar">
      <div className="search-box">
        <img src={searchIcon} alt="search" className="topbar-icon" />
        <input type="text" placeholder="URL 입력" />
        <img src={addURLIcon} alt="add-url" className="topbar-icon" />
      </div>

    {/* === 프로필 + 메뉴 === */}
    <div className="user-info" ref={menuRef}>
      {/* ▼ 아이콘 클릭 시 메뉴 토글 */}
      <div className="user-click-area" onClick={() => setMenuOpen(!menuOpen)}>
        <img src={profileIcon} alt="user" className="user-icon" />
        <span className="username">admin</span>
        <img src={profileMenuIcon} alt="menu" className="menu-arrow" />
      </div>

      {/* ▼ 드롭다운 메뉴 */}
      {menuOpen && (
        <div className="dropdown-menu">
          <button className="logout-btn" onClick={onLogout}>
            <FiLogOut className="logout-icon" />
            <span>Logout</span>
          </button>
        </div>
      )}
    </div>
  </div>

    {/* ===== 인사말 + 메인 콘텐츠 ===== */}
    <div className="main-container">
      <div className="header-section">
        <h1>Hello 👋</h1>
        <p className="subtitle">Let's start CTI analysis</p>
      </div>

      {/* ===== 메인 3개 박스 ===== */}
      <div className="main-box-grid">
        {/* 1️⃣ Your Sources */}
        <div className="main-box sources">  {/* 전체 카드 박스 */}
          <h2>Your Sources</h2>
          <div className="source-card">     {/* 내부 스크롤 되는 박스 */}
            {(file || url) ? (
              <div className="source-item">
                <img
                  src={file ? pdfIcon : linkIcon}
                  alt={file ? "pdf icon" : "url icon"}
                  className="source-icon"
                />
                <div>
                  <p className="file-name">{file ? file.name : url}</p>
                  <p className="file-desc">
                    업로드된 CTI 리포트 또는 URL이 여기에 표시됩니다.
                  </p>
                </div>
              </div>
            ) : (
              <p style={{ color: '#aaa', padding: '10px' }}>
                업로드된 항목이 없습니다.
              </p>
            )}
          </div>
        </div>

        {/* 2️⃣ Exported IoCs */}
        <div className="main-box iocs">
          <h2>Exported IoCs</h2>
          <div className="ioc-list">
            <div className="ioc-item">
              <strong>Domain</strong> — 도메인 리스트
            </div>
            <div className="ioc-item">
              <strong>IP</strong> — IP 주소 리스트
            </div>
            <div className="ioc-item">
              <strong>Hash</strong> — 파일 해시 (MD5, SHA256 등)
            </div>
          </div>
        </div>

        {/* 3️⃣ Generated Rule & Explain */}
        <div className="main-box rule">
          <h2>Generated Rule & Explain</h2>
          <div className="rule-box">
            <div className="rule-section">
              <h3>Generated Rule</h3>
              <p>생성된 Rule 내용이 여기에 표시됩니다.</p>
            </div>
            <div className="explain-section">
              <h3>Explain</h3>
              <p>LLM이 생성한 부연 설명이 여기에 표시됩니다.</p>
            </div>
            <div className="rule-actions">
              <button className="copy-btn">Copy</button>
              <button className="deploy-btn">Deploy</button>
            </div>
          </div>
        </div>
      </div> {/* ✅ main-box-grid 닫힘 */}
    </div> {/* ✅ main-container 닫힘 */}
  </>
);
}



export default MainView;

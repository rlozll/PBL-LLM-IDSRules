// src/components/Topbar.js
import React, { useState, useRef, useEffect, useCallback } from 'react';
import './Topbar.css';
import { ReactComponent as SearchIcon } from './icons/search.svg';
import { ReactComponent as ProfileIcon } from './icons/profile.svg';
import { ReactComponent as ProfileMenuIcon } from './icons/profileMenu.svg';
import { FiLogOut } from 'react-icons/fi';

// URL 리스트 직렬화하는데 사용되는 구분자
const URL_DELIMITER = '\n';

function Topbar({ url, setUrl, isLoading, onAnalyze, onLogout }) {  //  URL 등록 기능 상위 컴포넌트에서 받을 수도 있음
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef(null);

  // URL 목록 박스(드롭다운)의 표시 여부 상태 추가
  const [isBoxOpen, setIsBoxOpen] = useState(false);
  // 현재 Input 필드에 입력 중인 단일 URL을 위한 내부 상태
  const [currentInput, setCurrentInput] = useState('');
  const searchBoxRef = useRef(null);

  // url prop 리스트로 변환하는 함수
  const getUrlsList = useCallback(() => {
    return url
      ? url.split(URL_DELIMITER).map(u => u.trim()).filter(u => u.length > 0)
      : [];
  }, [url]);

  const urlsList = getUrlsList();

  const updateUrlsWithNew = (newUrl) => {
    const trimmedInput = newUrl.trim();
      if (trimmedInput) {
        // 새로운 URL이 이미 리스트에 있는지 확인 -> 중복 방지
        if (urlsList.includes(trimmedInput)) {
          // 이미 있다면 추가하지 않고 return
          return;
        }

        // 새로운 URL을 기존 리스트에 추가
        const newList = [...urlsList, trimmedInput];
        // 리스트를 URL prop으로 직렬화하여 부모 컴포넌트에 전달
        setUrl(newList.join(URL_DELIMITER));
      }
  };

  // URL을 리스트에 추가하고 prop 업데이트
  const submitUrl = () => {
    updateUrlsWithNew(currentInput);
    setCurrentInput(''); 
  }

  const addUrlFromExternal = useCallback((link) => {
    updateUrlsWithNew(link);
    setIsBoxOpen(true);
    setCurrentInput('');
  }, [urlsList, setUrl, updateUrlsWithNew]);

  // 리스트에서 URL 제거하는 함수
  const removeUrl = (indexToRemove) => {
    const newList = urlsList.filter((_, index) => index !== indexToRemove);
    // 리스트를 URL prop로 직렬화하여 부모 컴포넌트에 전달
    setUrl(newList.join(URL_DELIMITER));

    if (newList.length == 0) {
      setIsBoxOpen(false);
    }
  };

  const handleAnalyzeClick = () => {
    // 분석 시 현재 입력 중인 URL이 있다면 먼저 제출
    submitUrl();
    onAnalyze();
  }

  const handleInputKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      // Enter 키 누르면 URL 리스트에 제출
      submitUrl();
    }
  }

  // 드롭다운 외부 클릭 감지 로직
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (menuRef.current && !menuRef.current.contains(event.target)) {
        setMenuOpen(false);
      }

      // 검색 박스 드롭다운 닫기
      if (isBoxOpen && searchBoxRef.current && !searchBoxRef.current.contains(event.target)) {
        if (currentInput.trim()) {
          submitUrl();
        }
        setIsBoxOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isBoxOpen, currentInput, submitUrl]);

  return (
    <div className="topbar">
      <div className="search-container" ref={searchBoxRef}>
        <div className="search-box">
          <button onClick={handleAnalyzeClick} disabled={isLoading} className='topbar-icon'>
            {isLoading ? '...' : <SearchIcon />}
          </button>
          <input
            type="text"
            placeholder="https://..."
            value={currentInput}
            onChange={(e) => setCurrentInput(e.target.value)}
            onKeyDown={handleInputKeyDown}
            // 포커스 시 박스 열기
            onFocus={() => setIsBoxOpen(true)}
          />
        </div>

        {/* 드롭 다운 박스 렌더링 로직 */}
        {(isBoxOpen && urlsList.length > 0) && (
          <div className="url-dropdown-box">
            {urlsList.map((u, index) => (
              // 개별 URL 항목 컨테이너 (URL 텍스트 + 삭제 버튼)
              <div key={index} className="url-item-container">
                <div className="url-item-box">
                  {u}
                </div>
                {/* 삭제 버튼 */}
                <button
                  className="remove-url-btn"
                  onClick={() => removeUrl(index)}
                  aria-label="Remove URL"
                >
                  &times;
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="user-info" ref={menuRef} onClick={() => setMenuOpen(!menuOpen)}>
        <ProfileIcon alt="user" className="user-icon" />
        <span className="username">admin</span>
        <ProfileMenuIcon alt="menu" className="menu-arrow" />
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
  );
}

export default Topbar;

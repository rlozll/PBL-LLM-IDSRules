// src/components/Topbar.js
import React, { useState, useRef, useEffect } from 'react';
import './Topbar.css';
import searchIcon from './icons/search.svg';
import addURLIcon from './icons/addURL.svg';
import profileIcon from './icons/profile.svg';
import profileMenuIcon from './icons/profileMenu.svg';
import { FiLogOut } from 'react-icons/fi';

function Topbar({ onLogout, onAddURL }) {  //  URL 등록 기능 상위 컴포넌트에서 받을 수도 있음
  const [menuOpen, setMenuOpen] = useState(false);
  const [inputValue, setInputValue] = useState('');
  const menuRef = useRef(null);

  useEffect(() => {
    const handleClickOutside = (e) => {
      if (menuRef.current && !menuRef.current.contains(e.target)) {
        setMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleAddURL = () => {
    if (!inputValue.trim()) return;
    console.log("등록된 URL:", inputValue);
    if (onAddURL) onAddURL(inputValue); // 상위에서 props로 처리할 수도 있음
    setInputValue('');
  };

  return (
    <div className="topbar">
      <div className="search-box">
        <img src={searchIcon} alt="search" className="topbar-icon" />
        <input
          type="text"
          placeholder="URL 입력"
          value={inputValue}
          onChange={(e) => setInputValue(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              handleAddURL(); //  엔터 눌러도 등록 실행
            }
          }}
        />
        <img
          src={addURLIcon}
          alt="add-url"
          className="topbar-icon"
          onClick={handleAddURL} //  아이콘 클릭해도 등록
        />
      </div>

      <div 
        className="user-info" 
        ref={menuRef}
        onClick={() => setMenuOpen(!menuOpen)}
      >
        <img src={profileIcon} alt="user" className="user-icon" />
        <span className="username">admin</span>
        <img src={profileMenuIcon} alt="menu" className="menu-arrow" />

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

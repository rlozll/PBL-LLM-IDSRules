// src/components/Topbar.js
import React, { useState, useRef, useEffect } from 'react';
import './Topbar.css';
import searchIcon from './icons/search.svg';
import addURLIcon from './icons/addURL.svg';
import profileIcon from './icons/profile.svg';
import profileMenuIcon from './icons/profileMenu.svg';
import { FiLogOut } from 'react-icons/fi';

function Topbar({ onLogout }) {
  const [menuOpen, setMenuOpen] = useState(false);
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

  return (
    <div className="topbar">
      <div className="search-box">
        <img src={searchIcon} alt="search" className="topbar-icon" />
        <input type="text" placeholder="URL 입력" />
        <img src={addURLIcon} alt="add-url" className="topbar-icon" />
      </div>

      <div 
        className="user-info" 
        ref={menuRef}
        onClick={() => setMenuOpen(!menuOpen)} // 클릭 범위 확장
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
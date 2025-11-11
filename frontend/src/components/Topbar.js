// src/components/Topbar.js
import React, { useState, useRef } from 'react';
import './Topbar.css';
import { ReactComponent as SearchIcon } from './icons/search.svg';
import { ReactComponent as AddURLIcon } from './icons/addURL.svg';
import { ReactComponent as ProfileIcon } from './icons/profile.svg';
import { ReactComponent as ProfileMenuIcon } from './icons/profileMenu.svg';
import { FiLogOut } from 'react-icons/fi';

function Topbar({ url, setUrl, setFile, isLoading, onAnalyze, onLogout }) {  //  URL 등록 기능 상위 컴포넌트에서 받을 수도 있음
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef(null);
  const fileInputRef = useRef(null);

  const handleFileButtonClick = () => {
    fileInputRef.current.click();
  };

  const handleFileChange = (event) => {
    const selectedFile = event.target.files[0];
    if(selectedFile) {
      setFile(selectedFile);
      setUrl('');
      console.log('File selected:', selectedFile.name);
    }
  };

  const handleAnalyzeClick = () => {
    onAnalyze();
  }

  return (
    <div className="topbar">
      <div className="search-box">
        <button onClick={handleAnalyzeClick} disabled={isLoading} className='topbar-icon'>
          {isLoading ? '...' : <SearchIcon />}
        </button>
        <input
          type="text"
          placeholder="https://..."
          value={url}
          onChange={(e) => {
            setUrl(e.target.value);
            if (e.target.value) setFile(null);
          }}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              onAnalyze();
            }
          }}
        />
        <button onClick={handleFileButtonClick} disabled={isLoading} className="topbar-icon">
          <AddURLIcon />
        </button>
        <input
          type="file"
          ref={fileInputRef}
          onChange={handleFileChange}
          style={{ display: 'none' }}
          accept=".pdf, .txt"
        />
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

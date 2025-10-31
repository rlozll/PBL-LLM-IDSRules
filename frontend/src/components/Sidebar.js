// src/components/Sidebar.js
import React from 'react';

// 아이콘 라이브러리 (예: react-icons) 설치 필요: npm install react-icons
import { FiHome, FiList, FiSettings, FiClock, FiLogOut } from 'react-icons/fi';

function Sidebar({ currentView, setCurrentView, onLogout }) {
  const menuItems = [
    { id: 'main', label: '홈 화면', icon: <FiHome /> },
    { id: 'cti', label: 'CTI LIST', icon: <FiList /> },
    { id: 'settings', label: 'IDS 설정하기', icon: <FiSettings /> },
    { id: 'history', label: 'HISTORY', icon: <FiClock /> },
  ];

  return (
    <nav className="sidebar">
      {menuItems.map((item) => (
        <button
          key={item.id}
          className={currentView === item.id ? 'active' : ''}
          onClick={() => setCurrentView(item.id)}
        >
          {item.icon} <span style={{ marginLeft: '10px' }}>{item.label}</span>
        </button>
      ))}
       {/* 로그아웃 버튼 */}
      <button onClick={onLogout} style={{ marginTop: 'auto' }}> {/* 맨 아래로 보내기 */}
          <FiLogOut /> <span style={{ marginLeft: '10px' }}>Logout</span>
      </button>
    </nav>
  );
}

export default Sidebar;
// src/components/Sidebar.js
import React from 'react';

// 아이콘 라이브러리 (예: react-icons) 설치 필요: npm install react-icons
//mport { FiLogOut } from 'react-icons/fi';
import { ReactComponent as DashboardIcon } from './icons/DashboardHome.svg';
import { ReactComponent as CtiIcon } from './icons/CTILists.svg';
import { ReactComponent as BookmarkIcon } from './icons/BookmarkedLists.svg';
import { ReactComponent as HistoryIcon } from './icons/History.svg';
import { ReactComponent as LogoIcon } from './icons/Logo.svg';
import Footer from './Footer';
import './Sidebar.css';


function Sidebar({ currentView, setCurrentView }) {
  const menuItems = [
  { id: 'main', label: 'Dashboard', icon: <DashboardIcon className="sidebar-icon" /> },
  { id: 'cti', label: 'CTI LIST', icon: <CtiIcon className="sidebar-icon" /> },
  { id: 'bookmark', label: 'Bookmark', icon: <BookmarkIcon className="sidebar-icon" /> },
  { id: 'history', label: 'HISTORY', icon: <HistoryIcon className="sidebar-icon" /> },
];
  return (
    <nav className="sidebar">
       {/* ===== 상단 로고 영역 ===== */}
      <div className="sidebar-logo">
       <LogoIcon className="logo-icon" />
      </div>

       {/* ===== 메뉴 버튼들 ===== */}
      {menuItems.map((item) => (
        <button
          key={item.id}
          className={currentView === item.id ? 'active' : ''}
          onClick={() => setCurrentView(item.id)}
        >
          {item.icon} <span style={{ marginLeft: '10px' }}>{item.label}</span>
        </button>
      ))}
       {/* ✅ Footer 항상 하단 고정 */}
      <Footer />
    </nav>
  );
}

export default Sidebar;
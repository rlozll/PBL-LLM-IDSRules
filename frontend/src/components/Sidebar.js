// src/components/Sidebar.js
import React from 'react';

import { ReactComponent as DashboardIcon } from "../assets/DashboardLogo.svg";
import { ReactComponent as CtilistIcon } from "../assets/CtiListLogo.svg";
import { ReactComponent as BookmarkedIcon } from "../assets/BookmarkLogo.svg";
import { ReactComponent as HistoryIcon } from "../assets/HistoryLogo.svg";
import { ReactComponent as Logo } from "../assets/LOGO.svg";

function Sidebar({ currentView, setCurrentView, onLogout }) {
  const menuItems = [
    { id: 'main', label: 'Dashboard Home', icon: <DashboardIcon className="icon icon2"/> },
    { id: 'cti', label: 'CTI List', icon: <CtilistIcon className="icon"/> },
    { id: 'settings', label: 'Bookmarked Page', icon: <BookmarkedIcon className="icon"/> },
    { id: 'history', label: 'History', icon: <HistoryIcon className="icon icon2"/> },
  ];

  return (
    <nav className="sidebar">
      <Logo className="logo"/>
      {menuItems.map((item) => (
        <button
          key={item.id}
          className={currentView === item.id ? 'active' : ''}
          onClick={() => setCurrentView(item.id)}
        >
          {item.icon} <span style={{ marginLeft: '10px' }}>{item.label}</span>
        </button>
      ))}
      {/*<button onClick={onLogout} style={{ marginTop: 'auto' }}> 
          <FiLogOut /> <span style={{ marginLeft: '10px' }}>Logout</span>
      </button>*/}
      <footer className="footer">
        © 2025 CTINT. All rights reserved.
      </footer>
    </nav>
  );
}

export default Sidebar;
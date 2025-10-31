// src/App.js
import React, { useState, useEffect } from 'react';
import Login from './components/Login';
import Sidebar from './components/Sidebar';
import MainView from './components/MainView';
import CtiList from './components/CtiList';
import IdsSettings from './components/IdsSettings'; // 추가
import History from './components/History';
import { checkLoginStatus } from './api';
import './App.css'; // App 전체 스타일

function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  // 기본 뷰를 'main'으로 설정
  const [currentView, setCurrentView] = useState('main');
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const verifyLogin = async () => {
        const loggedIn = await checkLoginStatus();
        setIsLoggedIn(loggedIn);
        setIsLoading(false);
    };
    verifyLogin();
  }, []);

  const handleLoginSuccess = () => setIsLoggedIn(true);

  const handleLogout = () => {
     sessionStorage.removeItem('authToken');
     setIsLoggedIn(false);
     setCurrentView('main');
  }

  if (isLoading) return <div>Loading...</div>;

  if (!isLoggedIn) {
    return <Login onLoginSuccess={handleLoginSuccess} />;
  }

  // 로그인 후 대시보드 렌더링
  return (
    <div className="dashboard-layout">
      <Sidebar currentView={currentView} setCurrentView={setCurrentView} onLogout={handleLogout} />
      <main className="main-content">
        {currentView === 'main' && <MainView />}
        {currentView === 'cti' && <CtiList />}
        {currentView === 'settings' && <IdsSettings />} {/* 추가 */}
        {currentView === 'history' && <History />}
      </main>
    </div>
  );
}

export default App;
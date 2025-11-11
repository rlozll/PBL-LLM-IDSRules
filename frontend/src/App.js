// src/App.js
import React, { useState, useEffect } from 'react'; // <-- React 임포트는 파일 당 딱 한 번만!
import Login from './components/Login';
import Sidebar from './components/Sidebar';
import MainView from './components/MainView';
import CtiList from './components/CtiList';
import IdsSettings from './components/IdsSettings';
import History from './components/History';
import Topbar from './components/Topbar';

import { checkLoginStatus } from './api';
import './App.css';

function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [currentView, setCurrentView] = useState('main'); // 현재 뷰
  const [isLoading, setIsLoading] = useState(true); // 앱 로딩

  // --- MainView의 상태를 부모(App.js)로 이동 ---
  // (탭을 전환해도 이 정보가 사라지지 않도록)
  const [analysisResult, setAnalysisResult] = useState([]); // 여러 결과를 담기 위해 배열 '[]'로 초기화
  const [analysisError, setAnalysisError] = useState('');
  const [analysisLoading, setAnalysisLoading] = useState(false);

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

  return (
    <div className="dashboard-layout">
      <Sidebar currentView={currentView} setCurrentView={setCurrentView} onLogout={handleLogout} />
      <div className="main-top">
        <Topbar />
        <main className="main-content">
          {/* MainView에 상태와 상태 변경 함수를 props로 전달 */}
          {currentView === 'main' && (
            <MainView
              result={analysisResult}
              setResult={setAnalysisResult}
              error={analysisError}
              setError={setAnalysisError}
              isLoading={analysisLoading}
              setIsLoading={setAnalysisLoading}
            />
          )}
          {currentView === 'cti' && <CtiList />}
          {currentView === 'settings' && <IdsSettings />}
          {currentView === 'history' && <History />}
        </main>
      </div>
    </div>
  );
}

export default App;
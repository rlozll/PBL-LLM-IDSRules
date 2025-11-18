// src/App.js
import React, { useState, useEffect } from 'react'; // <-- React 임포트는 파일 당 딱 한 번만!
import Login from './components/Login';
import Sidebar from './components/Sidebar';
import MainView from './components/MainView';
import CtiList from './components/CtiList';
import IdsSettings from './components/IdsSettings';
import History from './components/History';
import Topbar from './components/Topbar';
import BookmarkedPages from './components/BookmarkedPages';  
import "./components/BookmarkedPages.css";  

import { checkLoginStatus, generateRule } from './api';
import './App.css';

function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [currentView, setCurrentView] = useState('main'); // 현재 뷰
  const [appIsLoading, setAppIsLoading] = useState(true); // 앱 로딩

  // --- MainView의 상태를 부모(App.js)로 이동 ---
  // (탭을 전환해도 이 정보가 사라지지 않도록)
  const [url, setUrl] = useState('');
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    const verifyLogin = async () => {
      const loggedIn = await checkLoginStatus();
      setIsLoggedIn(loggedIn);
      setAppIsLoading(false);
    };
    verifyLogin();
  }, []);

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

  const handleLoginSuccess = () => setIsLoggedIn(true);

  const handleLogout = () => {
     sessionStorage.removeItem('authToken');
     setIsLoggedIn(false);
     setCurrentView('main');
  }

  const handleBookmarkClick = (detailResult) => {
      // 1. 상세 결과를 배열로 감싸서 상태 업데이트 (MainView는 배열을 기대함)
      setResult(detailResult); 
      
      // 2. 에러 및 로딩 상태 초기화 (중요: 이전 상태가 남아있지 않도록)
      setError('');
      setIsLoading(false);
      
      // 3. 홈 화면으로 전환
      setCurrentView('main');
  };

  if (appIsLoading) return <div>Loading...</div>;

  if (!isLoggedIn) {
    return <Login onLoginSuccess={handleLoginSuccess} />;
  }

  return (
    <div className="dashboard-layout">
      <Sidebar currentView={currentView} setCurrentView={setCurrentView} onLogout={handleLogout} />
      <div className="main-top">
        <Topbar 
          url={url}
          setUrl={setUrl}
          file={file}
          setFile={setFile}
          isLoading={isLoading}
          onAnalyze={handleAnalyze}
          onLogout={handleLogout}
        />
        <main className="main-content">
          {/* MainView에 상태와 상태 변경 함수를 props로 전달 */}
          {currentView === 'main' && (
            <MainView
              result={result}
              error={error}
              isLoading={isLoading}
              url={url}
              file={file}
            />
          )}
          {currentView === 'cti' && <CtiList setCurrentView={setCurrentView} />}
          {currentView === 'settings' && (
            <BookmarkedPages 
                setCurrentView={setCurrentView} 
                onSelectBookmark={handleBookmarkClick} // <--- 새로 만든 함수 전달!
            />
          )}
          {currentView === 'history' && <History setCurrentView={setCurrentView} />}
        </main>
      </div>
    </div>
  );
}

export default App;
// src/App.js
import React, { useState, useEffect } from 'react';
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
  const [appIsLoading, setAppIsLoading] = useState(true);

  // --- MainView 상태 ---
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
  };

  // --- 북마크 클릭 시 MainView로 결과 전달 ---
  const handleBookmarkClick = (detailResult) => {
      setResult(detailResult);
      setError('');
      setIsLoading(false);
      setCurrentView('main');
  };

  // --- 히스토리 클릭 시 MainView로 결과 전달 ---
  const handleHistoryClick = (historyResult) => {
      setResult(historyResult);
      setUrl(historyResult.sources?.[0] || ""); // sources 배열의 첫 URL을 url로 넣음
      setError('');
      setIsLoading(false);
      setCurrentView('main');
  };



  if (appIsLoading) return <div>Loading...</div>;

  if (!isLoggedIn) return <Login onLoginSuccess={handleLoginSuccess} />;

  return (
    <div className="dashboard-layout">
      <Sidebar 
        currentView={currentView} 
        setCurrentView={setCurrentView} 
        onLogout={handleLogout} 
      />
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
                onSelectBookmark={handleBookmarkClick} 
            />
          )}
          {currentView === 'history' && (
            <History 
              setCurrentView={setCurrentView} 
              onSelectHistory={handleHistoryClick} 
            />
          )}
        </main>
      </div>
    </div>
  );
}

export default App;

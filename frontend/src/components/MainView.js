// src/components/MainView.js
import React, { useState, useRef } from 'react';
import { generateRule } from '../api';
import './MainView.css';
import { FiUpload } from 'react-icons/fi';

function MainView() {
  const [url, setUrl] = useState('');
  const [file, setFile] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const fileInputRef = useRef(null);

  const handleFileButtonClick = () => { fileInputRef.current.click(); };
  const handleFileChange = (event) => {
    const selectedFile = event.target.files[0];
    if (selectedFile) {
      setFile(selectedFile);
      setUrl('');
      console.log('File selected:', selectedFile.name);
    }
  };

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

  const handleCopyRule = () => {
    if (result && result.generated_rule) {
      navigator.clipboard.writeText(result.generated_rule);
      alert('Rule이 클립보드에 복사되었습니다.');
    }
  };

  const handleDeployRule = () => {
      if (result && result.validation_result.startsWith("Success")) {
          alert('배포 기능 호출 (구현 필요)');
      } else {
          alert('검증에 성공한 Rule만 배포할 수 있습니다.');
      }
  }

  // --- ▼▼▼▼▼ 설명 객체를 렌더링하는 헬퍼 함수 ▼▼▼▼▼ ---
  const renderExplanation = (explanation) => {
    // explanation이 문자열(오류 메시지 등)인 경우 그대로 표시
    if (typeof explanation === 'string') {
      return <p>{explanation}</p>;
    }
    // explanation이 객체인 경우 (성공 시)
    if (typeof explanation === 'object' && explanation !== null && !explanation.error) {
      return (
        <div>
          <h4>규칙 분석 (전문가용)</h4>
          <p>{explanation.rule_analysis}</p>
          <h4>IDS 설정 권장 사항</h4>
          <p>{explanation.ids_recommendation}</p>
          <h4>일반 사용자/개발자 조치 사항</h4>
          <p>{explanation.user_action}</p>
        </div>
      );
    }
    // explanation이 객체인데 오류가 포함된 경우
    if (explanation && explanation.error) {
      return <p style={{ color: 'red' }}>설명 생성 실패: {explanation.error}</p>;
    }
    // 그 외 알 수 없는 경우
    return <p>설명 데이터를 불러올 수 없습니다.</p>;
  };
  // --- ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲ ---

  return (
  <div className="main-container">
    <div className="main-box-grid">
      
      {/* ▼ 왼쪽 열 (URL 입력 + IoC) ▼ */}
      <div className="left-column">
        {/* === URL 입력 === */}
        <div className="analysis-box input-column">
          <h4>분석할 CTI URL 입력</h4>
          <div className="url-input-wrapper">
            <input
              type="text"
              value={url}
              onChange={(e) => {
                setUrl(e.target.value);
                if (e.target.value) setFile(null);
              }}
              placeholder="https://..."
              disabled={isLoading}
            />
            <button onClick={handleFileButtonClick} disabled={isLoading} className="upload-btn">
              <FiUpload />
            </button>
            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFileChange}
              style={{ display: 'none' }}
              accept=".pdf,.txt"
            />
          </div>
          <button
            onClick={handleAnalyze}
            disabled={isLoading || (!url && !file)}
            className="analyze-btn"
          >
            {isLoading ? '분석 중...' : '분석 시작'}
          </button>
          <div className="preview-box">
            {file
              ? `File: ${file.name}`
              : url
              ? `URL: ${url}`
              : 'url 페이지 or pdf 화면 출력'}
          </div>
        </div>

        {/* === IoC 박스 === */}
        <div className="analysis-box ioc-column">
          <h3>Exported IoCs</h3>
          {isLoading && <p>IoC를 추출 중입니다...</p>}
          {error && <p className="error-message">{error}</p>}
          {result && (
            <div className="ioc-grid">
              <div className="ioc-item">
                <strong>Domain:</strong>
                <pre>{JSON.stringify(result.extracted_ioc?.domain, null, 2)}</pre>
              </div>
              <div className="ioc-item">
                <strong>IP:</strong>
                <pre>{JSON.stringify(result.extracted_ioc?.ip, null, 2)}</pre>
              </div>
              <div className="ioc-item">
                <strong>Hash (SHA256):</strong>
                <pre>
                  {JSON.stringify(
                    result.extracted_ioc?.hash?.filter((h) => h.length === 64),
                    null,
                    2
                  )}
                </pre>
              </div>
              <div className="ioc-item">
                <strong>Hash (MD5):</strong>
                <pre>
                  {JSON.stringify(
                    result.extracted_ioc?.hash?.filter((h) => h.length === 32),
                    null,
                    2
                  )}
                </pre>
              </div>
              <div className="ioc-item">
                <strong>CVE:</strong>
                <pre>{JSON.stringify(result.extracted_ioc?.cve, null, 2)}</pre>
              </div>
            </div>
          )}
          {!isLoading && !result && !error && (
            <p>분석을 시작하면 IoCs가 여기에 표시됩니다.</p>
          )}
        </div>
      </div>

      {/* ▼ 오른쪽 열 (Rule & Explain) ▼ */}
      <div className="analysis-box rule-column">
        <div className="rule-outer-box">
        <h3>Generated Rule & Explain</h3>

          {isLoading && <p>Rule을 생성 중입니다...</p>}
          {error && <p className="error-message">Rule 생성 실패</p>}

          {/* === Generated Rule 카드 === */}
          <div className="rule-inner-card">
            <div className="rule-card-header">
              <span className="rule-icon">🧩</span>
              <h3>Generated Rule</h3>
            </div>
            <pre>{result?.generated_rule || '생성된 룰이 여기에 표시됩니다.'}</pre>
            <div className="validation-status">
              <strong>검증: </strong>
              <span
                style={{
                  color: result?.validation_result?.startsWith('Success')
                    ? 'lightgreen'
                    : result?.validation_result === 'Warning'
                    ? 'orange'
                    : '#ff6b6b',
                }}
              >
                {result?.validation_result || '대기 중'}
              </span>
            </div>
          </div>

          {/* === Explain 카드 === */}
          <div className="rule-inner-card">
            <div className="rule-card-header">
              <span className="rule-icon">💬</span>
              <h3>Explain</h3>
            </div>
            <div className="rule-explanation-scroll">
              {result
                ? renderExplanation(result.rule_explanation)
                : '분석 결과에 대한 설명이 여기에 표시됩니다.'}
            </div>
          </div>

          {/* === 하단 버튼 === */}
          <div className="rule-actions-v2">
            <button onClick={handleCopyRule}>Copy</button>
            <button onClick={handleDeployRule} className="deploy-btn">
              Deploy
            </button>
          </div>

          {/* === 분석 전 안내 메시지 === */}
          {!isLoading && !result && !error && (
            <p>분석을 시작하면 Rule이 여기에 표시됩니다.</p>
          )}
        </div>
      </div>
    </div>
  </div>
);
  

}

export default MainView;
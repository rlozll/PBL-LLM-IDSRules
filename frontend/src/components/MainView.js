// src/components/MainView.js
import React from 'react';
import './MainView.css';
import { ReactComponent as GeneratedSvg } from './icons/GeneratedRule.svg';
import { ReactComponent as ExplainSvg } from './icons/Explain.svg';
import { deployRule } from '../api';

function MainView({ result, error, isLoading, url }) {
  const handleCopyRule = () => {
    if (result && result.generated_rule) {
      navigator.clipboard.writeText(result.generated_rule);
      alert('Rule이 클립보드에 복사되었습니다.');
    }
  };

  const handleDeployRule = async () => {
    const ruleContent = result?.generated_rule;
    if (result && result.validation_result.startsWith("Success")) {
      try {
        const response = await deployRule(ruleContent);
        if(response.ok) {
          alert('Rule을 성공적으로 배포했습니다.');
        } else {
          const detail = response.data.detail;
          alert(`Rule 배포에 실패했습니다. ${detail}`);
        }
      } catch (error) {
        alert('네트워크 오류로 배포에 실패했습니다.');
      }
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
          <h4>① 규칙 분석 (전문가용)</h4>
          <p>{explanation.rule_analysis}</p>
          <h4>② IDS 설정 권장 사항</h4>
          <p>{explanation.ids_recommendation}</p>
          <h4>③ 일반 사용자/개발자 조치 사항</h4>
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

  const renderSources = () => {
    {/*if (file) {
      return (
        <div className="source-item">
          <span className="source-icon">📄</span>
          <div>
            <h4 className="file-name">{file.name}</h4>
          </div>
        </div>
      );
    }*/}
    if (url) {
      const urlList = url.split('\n').filter(u => u.trim() !== '');
      return urlList.map((url, index) => (
        <div key={index} className="source-item">
          <span className="source-icon">🔗</span>
          <div>
            <h4 className="file-name">{url}</h4>
          </div>
        </div>
      ));
    }
    if (!isLoading) {
      return <p>분석할 URL을 입력하세요.</p>
    }
    return null;
  }
  return (
  <div className="main-container">
    {/*<div className="header-section">
      <h1>Home</h1>
      <p className="subtitle">Let's start CTI analysis</p>
    </div>*/}
    <div className="main-box-grid">
      <div className="main-box sources">
        <h3>1. 소스 목록</h3>
        <div className="source-card">
          {renderSources()}
        </div>
      </div>
      <div className="main-box iocs">
        <h3>2. 추출된 IoCs</h3>
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

      {/* ▼ 오른쪽 열 (Rule & Explain) ▼ */}
      <div className="main-box rule">
          <h3>3. Rule 생성 및 설명</h3>

          {isLoading && <p>Rule을 생성 중입니다...</p>}
          {error && <p className="error-message">Rule 생성 실패</p>}

          {/* === Generated Rule 카드 === */}
          <div className="rule-inner-card">
            <div className="rule-card-header">
              {/*<span className="rule-icon">🧩</span>*/}
              <GeneratedSvg className="right-icon"/>
              <h3>3-1. Rule 생성</h3>
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
              <ExplainSvg className="right-icon" />
              {/*<span className="rule-icon">💬</span>*/}
              <h3>3-2. Rule 설명</h3>
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
);
  

}

export default MainView;
// src/components/MainView.js
import React, { useState } from 'react';
import { generateRule } from '../api';

function MainView() {
  const [url, setUrl] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const handleAnalyze = async () => {
    if (!url) return;
    setIsLoading(true);
    setResult(null);
    setError('');

    const response = await generateRule(url);

    if (response.ok) { // API 호출 성공 (HTTP 200)
        setResult(response.data);
    } else { // API 호출 실패 (HTTP 4xx, 5xx 등)
        const errorDetail = response.data?.detail?.error || response.data?.detail || `API Error (${response.status})`;
        setError(`분석 실패: ${errorDetail}`);
        console.error("Analysis failed:", response.status, response.data);
    }
    setIsLoading(false);
  };

  const handleCopyRule = () => { /* 이전과 동일 */ };
  const handleDeployRule = () => { /* 이전과 동일 */ };

  return (
    <div>
      <h2>CTI Rule 생성</h2> {/* 제목 변경 */}
      <div className="input-area">
        <input
          type="text"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="분석할 CTI URL 입력"
        />
        {/* 파일 업로드 UI 추가 필요 */}
        <button onClick={handleAnalyze} disabled={isLoading || !url}> {/* URL 없으면 비활성화 */}
          {isLoading ? '분석 중...' : '분석 시작'}
        </button>
      </div>

      {error && <div className="error-message" style={{marginTop:'15px'}}>{error}</div>} {/* 스타일 약간 추가 */}

      {/* 결과 표시 영역 (이전 코드와 거의 동일) */}
      {result && (
        <div className="result-area">
          <div className="source-display">
            <h4>Source</h4>
            <p>URL: <a href={result.source_url} target="_blank" rel="noopener noreferrer">{result.source_url}</a></p>
            {/* 여기에 URL 페이지 미리보기 iframe 또는 스크린샷 표시? */}
            {/* VT 요약 정보 표시 */}
            {result.vt_summary && (
                <>
                <h5>VirusTotal 요약</h5>
                <p>Status: {result.vt_summary.status}</p>
                {/* 필요시 더 많은 VT 정보 표시 */}
                </>
            )}
          </div>
          <div className="ioc-display">
            <h3>추출된 IoCs</h3>
            <pre>{JSON.stringify(result.extracted_ioc, null, 2)}</pre>
          </div>
          <div className="rule-display">
            <h3>생성된 Rule</h3>
            <pre>{result.generated_rule}</pre>
            <p><strong>검증:</strong> <span style={{ color: result.validation_result === 'Success: Valid Syntax' ? 'lightgreen' : (result.validation_result === 'Warning' ? 'orange' : 'red') }}>{result.validation_result}</span></p>
            {result.validation_details && <pre><strong>상세:</strong> {result.validation_details}</pre>}
             <p><strong>설명:</strong> {result.rule_explanation}</p>
             <button onClick={handleCopyRule}>Rule 복사</button>
             <button onClick={handleDeployRule}>Rule 배포</button>
          </div>
        </div>
      )}
    </div>
  );
}

export default MainView;
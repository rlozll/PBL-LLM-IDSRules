// src/components/MainView.js
import React, { useState } from 'react';
import { generateRule } from '../api';
import { MdOutlineFileUpload } from "react-icons/md";
import { MdOutlineFileOpen } from "react-icons/md";
import { IoCopyOutline } from "react-icons/io5";

function MainView() {
  const [url, setUrl] = useState('');
  const [file, setFile] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const handleFileUpload = (e) => {
    const uploadedFile = e.target.files[0];
    if(uploadedFile) {
      setFile(uploadedFile);
      setUrl(''); 
    }
  }

  const handleAnalyze = async () => {
    if (!url && !file) {
      setError("URL 또는 파일을 입력해주세요.")
      return;
    }
    setIsLoading(true);
    setResult(null);
    setError('');

    try {
      let response;
      if(file) {
        const formData = new FormData();
        formData.append('file', file);
        response = await generateRule(null, formData);
      } else {
        response = await generateRule(url);
      }

      if (response.ok) {
        setResult(response.data);
      } else {
        const errorDetail = response.data?.detail?.error || response.data?.detail || `API Error (${response.status})`;
        setError(`분석 실패: ${errorDetail}`);
        console.error("Analysis failed:", response.status, response.data);
      }
    } catch(err) {
      setError(`분석 중 오류 발생: ${err.message}`);
      console.error("Analysis error: ", err);
    }
    setIsLoading(false);
  };

  const handleCopyRule = () => {
    if (result?.generated_rule) {
      navigator.clipboard.writeText(result.generated_rule);
      alert('Rule이 클립보드에 복사되었습니다.');
    }
  };

  const handleDeployRule = () => {
    if (result?.generated_rule) {
      alert('Rule 배포 기능은 준비 중입니다.');
    }
  };

  const clearInput = () => {
    setUrl('');
    setFile(null);
    setResult(null);
    setError('');
  };

  return (
    <div className="main-view">
      <h2>CTI Rule 생성</h2>
      
      <div className="content-wrapper">
        <div className="left-section">
          <div className="input-area">
            <div className="url-input">
              <input
                type="text"
                value={url}
                onChange={(e) => {
                  setUrl(e.target.value);
                  setFile(null); 
                }}
                placeholder="분석할 CTI URL 입력"
                disabled={file !== null}
              />
              {url && (
                <button className="clear" onClick={clearInput}>✕</button>
              )}
              <label className="file-input">
                <MdOutlineFileUpload size={20} />
                <input
                  type="file"
                  accept=".pdf,.txt,.html,.json"
                  onChange={handleFileUpload}
                  style={{ display: 'none' }}
                />
              </label>
            </div>
            <button 
              className="analyze" 
              onClick={handleAnalyze} 
              disabled={isLoading || (!url && !file)}
            >
              {isLoading ? "분석 중..." : "분석 시작"}
            </button>
          </div>

          {error && <div className="error-message">{error}</div>}

          <div className="preview">
            {isLoading ? (
              <div className="preview-loading">
                <div className="spinner-small"></div>
                <p>소스 로딩 중...</p>
              </div>
            ) : result ? (
              <div className="preview-content">
                {url && !file && (
                  <div className="preview-url">
                    <div className="preview-header">
                      <span className="preview-icon">🔗</span>
                      <span className="preview-title">{url}</span>
                    </div>
                    <iframe
                      src={url}
                      title="URL Preview"
                      className="preview-iframe"
                      sandbox="allow-same-origin allow-scripts"
                    />
                  </div>
                )}
                {file && (
                  <div className="preview-file">
                    <div className="preview-header">
                      <span className="preview-icon">📄</span>
                      <span className="preview-title">{file.name}</span>
                      <span className="preview-size">{(file.size / 1024).toFixed(2)} KB</span>
                    </div>
                    {result?.source_text && (
                      <div className="preview-text">
                        <pre>{result.source_text}</pre>
                      </div>
                    )}
                    {result?.source_info && (
                      <div className="preview-info">
                        <p><strong>타입:</strong> {result.source_info.type}</p>
                        {result.source_info.title && (
                          <p><strong>제목:</strong> {result.source_info.title}</p>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </div>
            ) : (
              <div className="placeholder">
                <p>url 페이지 or pdf 화면 출력</p>
              </div>
            )}
          </div>
        </div>

        <div className="center-section">
          <h3>[추출된 IoCs]</h3>
          {isLoading ? (
            <div className="loading">
              <div className="spinner"></div>
              <p>분석 중...</p>
            </div>
          ) : result?.extracted_ioc ? (
            <div className="ioc-section-container">
              <div className="ioc-section">
                <label>• Domain:</label>
                <div className="ioc-print">
                  {result.extracted_ioc.domains?.length > 0 ? (  
                    result.extracted_ioc.domains.map((domain, idx) => (
                      <div key={idx} className="ioc-chip">{domain}</div>
                    ))
                  ) : (
                    <span className="empty-text">-</span> 
                  )}
                </div>
              </div>
              <div className="ioc-section">
                <label>• IP:</label>
                <div className="ioc-print">
                  {result.extracted_ioc.ips?.length > 0 ? (  
                    result.extracted_ioc.ips.map((ip, idx) => (
                      <div key={idx} className="ioc-chip">{ip}</div>
                    ))
                  ) : (
                    <span className="empty-text">-</span>
                  )}
                </div>
              </div>
              <div className="ioc-section">
                <label>• File hash (SHA256):</label>
                <div className="ioc-print">
                  {result.extracted_ioc.file_hashes?.sha256?.length > 0 ? (  
                    result.extracted_ioc.file_hashes.sha256.map((hash, idx) => (
                      <div key={idx} className="ioc-chip hash">{hash}</div>
                    ))
                  ) : (
                    <span className="empty-text">-</span>
                  )}
                </div>
              </div>
              <div className="ioc-section">
                <label>• File hash (md5):</label>
                <div className="ioc-print">
                  {result.extracted_ioc.file_hashes?.md5?.length > 0 ? (  
                    result.extracted_ioc.file_hashes.md5.map((hash, idx) => (
                      <div key={idx} className="ioc-chip hash">{hash}</div>
                    ))
                  ) : (
                    <span className="empty-text">-</span>
                  )}
                </div>
              </div>
              <div className="ioc-section">
                <label>• CVE:</label> 
                <div className="ioc-print">
                  {result.extracted_ioc.cves?.length > 0 ? (  
                    result.extracted_ioc.cves.map((cve, idx) => (
                      <div key={idx} className="ioc-chip">{cve}</div>
                    ))
                  ) : (
                    <span className="empty-text">-</span>
                  )}
                </div>
              </div>
            </div>
          ) : (
            <div className="empty">
              <p>분석을 시작하면 IoCs가 여기에 표시됩니다.</p>
            </div>
          )}
        </div>

        <div className="right-section">
          <h3>[Rule 생성]</h3>
          {isLoading ? (
            <div className="loading">
              <div className="spinner"></div>
              <p>분석 중...</p>
            </div>
          ) : result?.generated_rule ? ( 
            <div className="rule-content">
              <div className="rule-editor">
                <pre>{result.generated_rule}</pre>
              </div>
              <div className="rule-info">
                <p className="validation-status">
                  <strong>검증:</strong> 
                  <span className={`status ${
                    result.validation_result === 'Success: Valid Syntax' ? 'success' : 
                    result.validation_result === 'Warning' ? 'warning' : 'error'
                  }`}>
                    {result.validation_result}
                  </span>
                </p>
                {result.rule_explanation && (
                  <p className="rule-explanation">
                    <strong>설명:</strong> {result.rule_explanation}
                  </p>
                )}
              </div>
              <div className="rule-actions">
                <button className="btn-secondary" onClick={handleCopyRule}>
                  <IoCopyOutline size={18} />
                  Rule 복사
                </button>
                <button className="btn-primary" onClick={handleDeployRule}>
                  <MdOutlineFileOpen size={18} />
                  Rule 배포
                </button>
              </div>
            </div>
          ) : (
            <div className="empty">
              <p>분석을 시작하면 Rule이 여기에 표시됩니다.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default MainView;
// src/components/CtiList.js
import React, { useState, useEffect } from 'react';
import { getNewCtiList } from '../api'; // api.js에서 함수 가져오기

function CtiList() {
  const [ctiItems, setCtiItems] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedItem, setSelectedItem] = useState(null);

  useEffect(() => {
    const fetchList = async () => {
      try {
        setIsLoading(true);
        setError(null);
        // API 호출 (가정: [{ title: "...", link: "...", ... }])
        const items = await getNewCtiList(); 

        const itemsWithId = items.map((item, index) => ({
          ...item,
          id: index, // 고유 ID가 없다면 임시 ID 사용
        }));
        
        setCtiItems(itemsWithId);
      } catch (err) {
        setError("CTI 리스트 로딩에 실패했습니다.");
        console.error(err);
      } finally {
        setIsLoading(false);
      }
    };
    fetchList();
  }, []);

  const handleItemClick = (item) => {
    setSelectedItem(item);
  };

  const handleDeleteItem = (itemId, e) => {
    e.stopPropagation(); // 부모 클릭 이벤트 전파 방지
    // 삭제 로직 구현
    setCtiItems(ctiItems.filter(item => item.id !== itemId));
    if (selectedItem?.id === itemId) {
      setSelectedItem(null);
    }
  };

  if (isLoading) {
    return (
      <div className="cti-loading-container">
        <div className="spinner"></div>
        <p>Loading CTI List...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="cti-error-container">
        <p>{error}</p>
      </div>
    );
  }

  return (
    <div className="cti-page-container">
      {/* 왼쪽: CTI 리스트 */}
      <div className="cti-list-panel">
        {ctiItems.length === 0 ? (
          <div className="cti-empty">
            <p>새로운 CTI 정보가 없습니다.</p>
          </div>
        ) : (
          <div className="cti-items-container">
            {ctiItems.map((item) => (
              <div
                key={item.id}
                className={`cti-item-card ${selectedItem?.id === item.id ? 'active' : ''}`}
                onClick={() => handleItemClick(item)}
              >
                <div className="cti-item-header">
                  <div className="cti-item-icon">🔔</div>
                  <button 
                    className="cti-item-delete"
                    onClick={(e) => handleDeleteItem(item.id, e)}
                    title="삭제"
                  >
                    ✕
                  </button>
                </div>
                <div className="cti-item-content">
                  {/* [수정] title이 없다면 link를 제목으로 사용 */}
                  <h4 className="cti-item-title">{item.title || item.link || "제목 없음"}</h4>
                  {/*<p className="cti-item-source">
                    {item.source || '출처 정보'}
                  </p>
                  <p className="cti-item-date">
                    {item.published_date || item.date || '날짜 정보'}
                  </p>*/}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* 오른쪽: 상세 내용 (iframe으로 변경) */}
      <div className="cti-detail-panel">
        {selectedItem ? (
          // [수정] 상세 요약 대신 iframe으로 웹사이트 원본 표시
          <iframe
            src={selectedItem.link}
            title={selectedItem.title || 'CTI Content'}
            className="cti-detail-iframe"
            // sandbox 속성을 추가하여 보안 강화 (필요시 'allow-scripts' 등 추가)
            sandbox="allow-same-origin" 
          />
        ) : (
          // 선택된 아이템이 없을 때
          <div className="cti-detail-empty">
            <div className="empty-icon">📋</div>
            <p>왼쪽 목록에서 CTI 항목을 선택하세요.</p>
          </div>
        )}
      </div>
    </div>
  );
}

export default CtiList;
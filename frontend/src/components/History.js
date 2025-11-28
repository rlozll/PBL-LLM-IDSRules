import React, { useState, useEffect } from "react";
import "./History.css";
import { getHistoryRecords, getHistoryDetail } from "../api";

const History = ({ setCurrentView, onSelectHistory }) => {
  const [historyData, setHistoryData] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const fetchHistory = async () => {
      setIsLoading(true);
      setError("");
      try {
        const records = await getHistoryRecords();
        setHistoryData(records || []);
      } catch (e) {
        setError("히스토리를 불러오는 데 실패했습니다.");
      }
      setIsLoading(false);
    };
    fetchHistory();
  }, []);

  // 클릭 시 HomeView로 이동 + 선택 기록 전달
  const handleRowClick = async (id) => {
    try {
      const detail = await getHistoryDetail(id);
      if (detail) {
        onSelectHistory(detail); // App.js에서 HomeView에 전달
        setCurrentView("main");  // HomeView로 이동
      } else {
        alert("상세 데이터를 불러오지 못했습니다.");
      }
    } catch (e) {
      console.error(e);
      alert("상세 데이터를 가져오는 중 오류가 발생했습니다.");
    }
  };

  const sortedHistory = [...historyData].sort(
    (a, b) => new Date(b.created_at) - new Date(a.created_at)
  );

  const limitedHistory = sortedHistory.slice(0, 20);


  return (
    <div className="history-container">
      <div className="history-header">
        <h1>History</h1>
        <p className="subtitle">Look at past records</p>
      </div>

      {isLoading && <p>Loading...</p>}
      {error && <p className="error-message">{error}</p>}

      <div className="history-table">
        <div className="history-table-header">
          <div>분석 제목 (Title)</div>
          <div>생성된 Rule</div>
          <div>Date</div>
        </div>
        <div className="history-table-body">
          {limitedHistory.map((item) => (
            <div
              className="history-row"
              key={item.id}
              onClick={() => handleRowClick(item.id)}
              style={{ cursor: "pointer" }}
            >
              <div className="col-title">
                <a 
                  href={item.source_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  onClick={(e) => e.stopPropagation()}  
                  className="history-link"
                >
                  {item.source_url}
                </a>
              </div>
              <div className="col-rule">{item.generated_rule || "분석 중..."}</div>
              <div className="col-date">
                {new Date(item.created_at).toLocaleDateString("ko-KR")}
              </div>
            </div>
          ))}
        </div>
       </div> 
      </div>
  );
};

export default History;

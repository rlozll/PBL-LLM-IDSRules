// --- src/components/History.js ---
import React, { useState, useEffect } from 'react';
import { getHistory } from '../api';
function History() {
  const [historyItems, setHistoryItems] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  useEffect(() => { /* CtiList와 유사하게 getHistory() 호출 */ }, []);
  if (isLoading) return <div>Loading History...</div>;
  return <div><h2>생성 기록</h2><p>과거 생성된 Rule 목록 (구현 예정).</p></div>;
}
export default History;
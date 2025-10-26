// src/components/CtiList.js (나머지 파일들도 비슷하게)
import React, { useState, useEffect } from 'react';
import { getNewCtiList } from '../api'; // api.js에서 함수 가져오기

function CtiList() {
  const [ctiItems, setCtiItems] = useState([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const fetchList = async () => {
      setIsLoading(true);
      const items = await getNewCtiList(); // 백엔드 호출
      setCtiItems(items);
      setIsLoading(false);
    };
    fetchList();
  }, []); // 컴포넌트 마운트 시 1회 실행

  if (isLoading) return <div>Loading CTI List...</div>;

  return (
    <div>
      <h2>새로운 CTI 리스트</h2>
      {ctiItems.length === 0 ? (
        <p>새로운 CTI 정보가 없습니다.</p>
      ) : (
        <ul>
          {/* 받아온 ctiItems 배열을 리스트로 표시 */}
          {ctiItems.map((item, index) => (
            <li key={index}>
              {/* 백엔드가 보내주는 필드에 맞게 수정 */}
              <a href={item.link} target="_blank" rel="noopener noreferrer">{item.title}</a> ({item.published_date})
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
export default CtiList;